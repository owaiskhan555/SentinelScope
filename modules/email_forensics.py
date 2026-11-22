"""RFC-5322 Email Header, Authentication (SPF/DKIM/DMARC), Routing & IOC Forensics Engine."""

from __future__ import annotations

import email
import hashlib
import os
import re
from datetime import datetime, timezone
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".link", ".work", ".support", ".review", ".country",
}

PHISHING_KEYWORDS = {
    "verify", "login", "signin", "secure", "account", "update", "confirm",
    "suspend", "suspended", "urgent", "invoice", "payment", "password", "wallet",
    "mfa", "2fa", "unlock", "billing", "security-alert",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
    ".hta", ".iso", ".img", ".lnk", ".dll", ".msi", ".docm", ".xlsm", ".pptm",
    ".zip", ".rar", ".7z", ".html", ".htm",
}

KNOWN_BRANDS = {
    "microsoft", "office365", "google", "gmail", "paypal", "apple", "amazon",
    "dhl", "fedex", "dropbox", "docusign", "stripe", "cloudflare", "github",
}


def _extract_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower().strip(">")


def _parse_auth_results(msg: email.message.EmailMessage) -> dict:
    """Parse SPF, DKIM, and DMARC verdicts from Authentication-Results / Received-SPF headers."""
    auth_headers = msg.get_all("Authentication-Results", [])
    spf_headers = msg.get_all("Received-SPF", [])
    dkim_sigs = msg.get_all("DKIM-Signature", [])

    combined_auth = " | ".join(auth_headers).lower()
    combined_spf = " | ".join(spf_headers).lower()

    def _find_verdict(proto: str, text: str) -> str:
        match = re.search(rf"\b{proto}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", text)
        if match:
            return match.group(1).upper()
        return "MISSING"

    spf_status = _find_verdict("spf", combined_auth)
    if spf_status == "MISSING" and combined_spf:
        m_spf = re.match(r"^\s*(pass|fail|softfail|neutral|none)", combined_spf)
        if m_spf:
            spf_status = m_spf.group(1).upper()

    dkim_status = _find_verdict("dkim", combined_auth)
    dmarc_status = _find_verdict("dmarc", combined_auth)

    dkim_domains = []
    for sig in dkim_sigs:
        d_match = re.search(r"\bd=([^;\s]+)", sig)
        if d_match:
            dkim_domains.append(d_match.group(1).strip())

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "dkim_signature_present": len(dkim_sigs) > 0,
        "dkim_signing_domains": list(dict.fromkeys(dkim_domains)),
        "raw_auth_headers": auth_headers,
    }


def _trace_received_hops(msg: email.message.EmailMessage) -> tuple[list[dict], list[str]]:
    """Reconstruct chronological mail server hops from Received headers."""
    raw_received = msg.get_all("Received", [])
    # Received headers are prepended top-down; reverse to get origin -> destination
    chronological = list(reversed(raw_received))

    hops = []
    all_ips = []
    prev_dt = None

    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    for idx, hdr in enumerate(chronological, start=1):
        clean_hdr = " ".join(hdr.split())
        from_match = re.search(r"\bfrom\s+([^\s\(\);]+)", clean_hdr, flags=re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s\(\);]+)", clean_hdr, flags=re.IGNORECASE)
        with_match = re.search(r"\bwith\s+([A-Za-z0-9\-]+)", clean_hdr, flags=re.IGNORECASE)

        ips_in_hop = ip_pattern.findall(clean_hdr)
        for ip in ips_in_hop:
            if ip not in all_ips:
                all_ips.append(ip)

        timestamp_str = "Not specified"
        delay_str = "—"
        if ";" in clean_hdr:
            date_part = clean_hdr.rsplit(";", 1)[1].strip()
            timestamp_str = date_part
            try:
                curr_dt = parsedate_to_datetime(date_part)
                if curr_dt.tzinfo is None:
                    curr_dt = curr_dt.replace(tzinfo=timezone.utc)
                if prev_dt is not None:
                    delta_sec = (curr_dt - prev_dt).total_seconds()
                    if delta_sec >= 0:
                        delay_str = f"+{delta_sec:.1f}s" if delta_sec < 120 else f"+{delta_sec/60:.1f}m"
                    else:
                        delay_str = f"{delta_sec:.1f}s (Clock skew)"
                prev_dt = curr_dt
            except Exception:
                pass

        hops.append(
            {
                "Hop": idx,
                "From Server": from_match.group(1) if from_match else "Origin Client",
                "By Relay": by_match.group(1) if by_match else "Unknown",
                "Relay IPs": ", ".join(ips_in_hop) if ips_in_hop else "None listed",
                "Protocol": with_match.group(1).upper() if with_match else "SMTP",
                "Transit Delay": delay_str,
                "Timestamp": timestamp_str,
            }
        )

    return hops, all_ips


def _analyze_urls_and_bodies(msg: email.message.EmailMessage) -> tuple[list[dict], list[dict]]:
    """Extract body text, URLs, anchor-text mismatches, punycode domains, and attachments."""
    plain_parts = []
    html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            cdisp = part.get_content_disposition()
            ctype = part.get_content_type()
            filename = part.get_filename()

            if cdisp == "attachment" or filename:
                payload = part.get_payload(decode=True) or b""
                fname = filename or "unnamed_attachment.bin"
                ext = os.path.splitext(fname)[1].lower()
                attachments.append(
                    {
                        "Filename": fname,
                        "MIME Type": ctype,
                        "Size (Bytes)": len(payload),
                        "Risk Flag": "HIGH RISK EXTENSION" if ext in HIGH_RISK_EXTENSIONS else "Standard",
                        "SHA-256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            elif ctype == "text/plain":
                try:
                    plain_parts.append(part.get_content())
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
            if ctype == "text/html":
                html_parts.append(content)
            else:
                plain_parts.append(content)
        except Exception:
            pass

    full_plain = "\n".join(plain_parts)
    full_html = "\n".join(html_parts)

    url_records = []
    seen_urls = set()

    # Check HTML <a href="...">visible text</a> pairs for deceptive link masking
    anchor_pattern = re.compile(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        flags=re.IGNORECASE | re.DOTALL,
    )
    masked_targets = {}
    for href, inner_html in anchor_pattern.findall(full_html):
        visible_text = re.sub(r"<[^>]+>", "", inner_html).strip()
        if visible_text.lower().startswith(("http://", "https://")):
            vis_host = urlparse(visible_text).hostname or ""
            href_host = urlparse(href).hostname or ""
            if vis_host and href_host and vis_host.lower() != href_host.lower():
                masked_targets[href.strip()] = f"Visible text claims '{vis_host}' -> redirects to '{href_host}'"

    raw_urls = re.findall(r'https?://[^\s<>"\'\)]+', full_plain + "\n" + full_html)
    for raw_u in raw_urls:
        clean_u = raw_u.rstrip(".,;:")
        if clean_u in seen_urls:
            continue
        seen_urls.add(clean_u)

        parsed = urlparse(clean_u)
        host = (parsed.hostname or "").lower()
        flags = []

        if parsed.scheme == "http":
            flags.append("Unencrypted HTTP")
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
            flags.append("IP-Literal Host")
        if "xn--" in host or any(ord(ch) > 127 for ch in host):
            flags.append("IDN Homograph / Punycode")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append("High-Risk TLD")
        if any(kw in clean_u.lower() for kw in PHISHING_KEYWORDS):
            flags.append("Credential/Urgency Keyword")
        if clean_u in masked_targets:
            flags.append(f"Href Mismatch ({masked_targets[clean_u]})")

        url_records.append(
            {
                "URL": clean_u,
                "Domain": host or "Invalid",
                "Scheme": parsed.scheme.upper(),
                "Forensic Flags": ", ".join(flags) if flags else "Clean",
                "is_suspicious": len(flags) > 0,
            }
        )

    return url_records, attachments


def analyze_eml_bytes(raw_bytes: bytes, source_filename: str = "message.eml") -> dict:
    """Perform full forensic triage on an RFC-5322 .eml email file."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    subject = str(msg.get("Subject", "(No Subject)"))
    date_hdr = str(msg.get("Date", "Unknown"))
    message_id = str(msg.get("Message-ID", "Missing"))
    x_mailer = str(msg.get("X-Mailer", msg.get("User-Agent", "Not disclosed")))

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_addr)
    return_domain = _extract_domain(return_addr)

    auth = _parse_auth_results(msg)
    hops, relay_ips = _trace_received_hops(msg)
    urls, attachments = _analyze_urls_and_bodies(msg)

    # Calculate deterministic forensic risk score (0 - 100)
    risk_score = 0
    indicators = []

    if auth["spf"] in {"FAIL", "SOFTFAIL"}:
        risk_score += 25
        indicators.append(f"SPF Verification {auth['spf']}: Sending mail server is not authorized by '{from_domain}'.")
    elif auth["spf"] == "MISSING":
        risk_score += 8
        indicators.append("Missing SPF authentication result header.")

    if auth["dkim"] == "FAIL":
        risk_score += 25
        indicators.append("DKIM Cryptographic Signature FAILED: Message headers or body failed signature verification.")
    elif not auth["dkim_signature_present"] and auth["dkim"] == "MISSING":
        risk_score += 8
        indicators.append("No DKIM-Signature header attached to message.")

    if auth["dmarc"] == "FAIL":
        risk_score += 25
        indicators.append("DMARC Policy FAILED: Sender domain alignment check failed.")

    if return_domain and from_domain and return_domain != from_domain:
        risk_score += 18
        indicators.append(
            f"Envelope Return-Path Mismatch: Header 'From' is '{from_domain}' but bounce 'Return-Path' is '{return_domain}'."
        )

    if reply_domain and from_domain and reply_domain != from_domain:
        risk_score += 20
        indicators.append(
            f"Reply-To Hijack Indicator: Replies redirect to '{reply_domain}' instead of '{from_domain}'."
        )

    # Check display name brand impersonation
    disp_lower = from_name.lower()
    for brand in KNOWN_BRANDS:
        if brand in disp_lower and from_domain and brand not in from_domain:
            risk_score += 25
            indicators.append(
                f"Brand Display-Name Spoofing: Display name claims '{from_name}' but actual sender domain is '{from_domain}'."
            )
            break

    suspicious_urls = [u for u in urls if u["is_suspicious"]]
    if suspicious_urls:
        risk_score += min(30, 12 * len(suspicious_urls))
        for su in suspicious_urls[:4]:
            indicators.append(f"Suspicious URL Detected ({su['Forensic Flags']}): {su['URL']}")

    risky_attachments = [a for a in attachments if a["Risk Flag"] != "Standard"]
    if risky_attachments:
        risk_score += 30
        for ra in risky_attachments:
            indicators.append(f"High-Risk Attachment Extension: '{ra['Filename']}' (SHA-256: {ra['SHA-256'][:16]}...)")

    risk_score = min(100, risk_score)

    if risk_score >= 65:
        verdict = "HIGH RISK (PHISHING / SPOOFED)"
    elif risk_score >= 35:
        verdict = "SUSPICIOUS (REVIEW REQUIRED)"
    elif risk_score >= 15:
        verdict = "LOW RISK (MINOR ANOMALIES)"
    else:
        verdict = "AUTHENTIC / CLEAN"

    raw_headers_list = [f"{k}: {v}" for k, v in msg.items()]

    return {
        "analyzed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source_filename": source_filename,
        "eml_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "risk_score": risk_score,
        "verdict": verdict,
        "indicators": indicators,
        "headers": {
            "subject": subject,
            "date": date_hdr,
            "message_id": message_id,
            "x_mailer": x_mailer,
            "from_display": from_name or "(None)",
            "from_address": from_addr or "Missing",
            "from_domain": from_domain or "Unknown",
            "reply_to": reply_addr or "Same as From",
            "return_path": return_addr or "Not specified",
        },
        "auth": auth,
        "hops": hops,
        "relay_ips": relay_ips,
        "urls": urls,
        "attachments": attachments,
        "raw_headers_text": "\n".join(raw_headers_list),
    }
