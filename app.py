"""SentinelScope — Enterprise File Integrity & Email Threat Forensics Platform."""

import json
import os
import pandas as pd
import plotly.graph_objects as go  
import streamlit as st  

from modules import (
    analyze_eml_bytes,
    build_html_audit_report,
    calculate_avalanche_metrics,
    compute_sha256,
    create_batch_baseline,
    extract_byte_diff,
    verify_batch_files,
)

st.set_page_config(
    page_title="SentinelScope | Integrity & Threat Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Clean Enterprise SOC Styling
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, #0F172A, #162033);
        border: 1px solid #26334D;
        padding: 14px 18px;
        border-radius: 10px;
    }
    .verdict-clean {
        background-color: rgba(16, 185, 129, 0.14);
        border: 1px solid #10B981;
        color: #A7F3D0;
        padding: 12px 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    .verdict-warn {
        background-color: rgba(245, 158, 11, 0.14);
        border: 1px solid #F59E0B;
        color: #FDE68A;
        padding: 12px 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    .verdict-danger {
        background-color: rgba(239, 68, 68, 0.16);
        border: 1px solid #EF4444;
        color: #FECACA;
        padding: 12px 16px;
        border-radius: 8px;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "email_history" not in st.session_state:
    st.session_state["email_history"] = []

# Sidebar — Pure Operational Telemetry & Report Export
with st.sidebar:
    st.markdown("## 🛡️ SentinelScope")
    st.caption("File Integrity & Email Threat Forensics")
    st.divider()

    batch_res_state = st.session_state.get("last_batch_result")
    files_scanned = batch_res_state["total_checked"] if batch_res_state else 0
    files_tampered = batch_res_state["tampered_count"] if batch_res_state else 0

    emails_scanned = len(st.session_state["email_history"])
    phishing_flagged = sum(
        1 for r in st.session_state["email_history"] if r["risk_score"] >= 35
    )

    st.markdown("### Session Telemetry")
    s1, s2 = st.columns(2)
    s1.metric("Files Checked", files_scanned)
    s2.metric("Tampered", files_tampered)

    s3, s4 = st.columns(2)
    s3.metric("Emails Audited", emails_scanned)
    s4.metric("Threats Flagged", phishing_flagged)

    st.divider()
    st.markdown("### Compliance Export")
    audit_html = build_html_audit_report(
        batch_res_state,
        st.session_state["email_history"],
    )
    st.download_button(
        label="📥 Export Audit Report (.html)",
        data=audit_html,
        file_name="SentinelScope_Forensic_Report.html",
        mime="text/html",
        use_container_width=True,
    )

# Main Header
st.title("🛡️ SentinelScope: File Integrity & Email Forensics Suite")
st.caption(
    "SHA-256 Cryptographic File Integrity Monitoring • RFC-5322 Email Header, Authentication & IOC Analysis"
)

tab1, tab2 = st.tabs(
    [
        "🔐 File Integrity Monitor",
        "📧 Email & Phishing Forensics (.eml)",
    ]
)

# ==============================================================================
# TAB 1: FILE INTEGRITY MONITOR (UNCHANGED CORE LOGIC)
# ==============================================================================
with tab1:
    st.subheader("Cryptographic File Integrity & Bit-Level Avalanche Analyzer")
    st.write(
        "Generate SHA-256 baselines for critical files, verify batch integrity, and inspect bit-level hexadecimal differences."
    )

    f_col1, f_col2 = st.columns(2)

    with f_col1:
        st.markdown("### 1. Create Trusted Baseline")
        base_files = st.file_uploader(
            "Upload one or more reference files",
            accept_multiple_files=True,
            key="batch_base_files",
        )
        batch_label = st.text_input("Baseline Identifier", value="Baseline_Snapshot_v1")

        if base_files:
            items = [(f.name, f.getvalue()) for f in base_files]
            manifest = create_batch_baseline(items, batch_label)
            st.session_state["batch_manifest"] = manifest
            st.session_state["batch_raw_map"] = {name: data for name, data in items}

            st.success(
                f"Baseline locked for **{manifest['file_count']} file(s)** ({manifest['total_bytes']:,} bytes)."
            )
            st.download_button(
                label="📥 Download Baseline Manifest (.json)",
                data=json.dumps(manifest, indent=2),
                file_name=f"{batch_label}.baseline.json",
                mime="application/json",
            )

    with f_col2:
        st.markdown("### 2. Verify Target Files")
        uploaded_manifest = st.file_uploader(
            "Upload Baseline JSON (or use active session baseline)",
            type=["json"],
            key="batch_manifest_up",
        )
        suspect_files = st.file_uploader(
            "Upload file(s) to verify against baseline",
            accept_multiple_files=True,
            key="batch_suspect_files",
        )

        active_manifest = None
        if uploaded_manifest is not None:
            try:
                active_manifest = json.loads(uploaded_manifest.getvalue().decode("utf-8"))
            except Exception:
                st.error("Invalid JSON baseline manifest.")
        elif "batch_manifest" in st.session_state:
            active_manifest = st.session_state["batch_manifest"]
            st.caption(f"Active Baseline: `{active_manifest['label']}` ({active_manifest['file_count']} files)")

        if active_manifest and suspect_files:
            try:
                sus_items = [(f.name, f.getvalue()) for f in suspect_files]
                batch_res = verify_batch_files(active_manifest, sus_items)
                st.session_state["last_batch_result"] = batch_res

                g_col, t_col = st.columns([1, 2])
                with g_col:
                    fig_int = go.Figure(
                        go.Indicator(
                            mode="gauge+number",
                            value=batch_res["integrity_score"],
                            number={"suffix": "%"},
                            title={"text": "Integrity Score"},
                            gauge={
                                "axis": {"range": [0, 100]},
                                "bar": {"color": "#00E5FF"},
                                "steps": [
                                    {"range": [0, 50], "color": "#450A0A"},
                                    {"range": [50, 99], "color": "#451A03"},
                                    {"range": [99, 100], "color": "#064E3B"},
                                ],
                            },
                        )
                    )
                    fig_int.update_layout(
                        height=220,
                        margin=dict(l=15, r=15, t=40, b=10),
                        paper_bgcolor="rgba(0,0,0,0)",
                        font={"color": "#F1F5F9"},
                    )
                    st.plotly_chart(fig_int, use_container_width=True)

                with t_col:
                    st.dataframe(pd.DataFrame(batch_res["records"]), use_container_width=True, hide_index=True)

                raw_map = st.session_state.get("batch_raw_map", {})
                for fname, fbytes in sus_items:
                    if fname in raw_map and compute_sha256(raw_map[fname]) != compute_sha256(fbytes):
                        diffs = extract_byte_diff(raw_map[fname], fbytes)
                        if diffs:
                            st.error(f"Forensic Byte-Level Hex & Binary Diff for `{fname}`:")
                            st.dataframe(pd.DataFrame(diffs), use_container_width=True, hide_index=True)
            except ValueError as err:
                st.error(str(err))

    if "batch_raw_map" in st.session_state and st.session_state["batch_raw_map"]:
        st.divider()
        st.markdown("### Cryptographic Avalanche Verification (1-Bit Mutation Test)")
        sample_name = next(iter(st.session_state["batch_raw_map"]))
        orig_bytes = st.session_state["batch_raw_map"][sample_name]

        if st.button(f"Simulate 1-Bit Modification in `{sample_name}`", type="primary"):
            tampered_bytes = bytearray(orig_bytes)
            if len(tampered_bytes) > 0:
                tampered_bytes[0] ^= 0x01
            else:
                tampered_bytes.append(0x41)
            tampered_bytes = bytes(tampered_bytes)

            h_orig = compute_sha256(orig_bytes)
            h_tamp = compute_sha256(tampered_bytes)
            av = calculate_avalanche_metrics(h_orig, h_tamp)
            diffs = extract_byte_diff(orig_bytes, tampered_bytes)

            a1, a2, a3 = st.columns(3)
            a1.metric("Input Mutation", "1 Bit", "0.125 Bytes")
            a2.metric("Digest Bits Flipped", f"{av['flipped_bits']} / 256 bits", f"{av['flip_percentage']}% Avalanche")
            a3.metric("Theoretical Ideal", "50.0%", "SHA-256 Diffusion")

            st.code(
                f"Original SHA-256 : {h_orig}\n"
                f"Modified SHA-256 : {h_tamp}",
                language="text",
            )

            c_chart, c_hex = st.columns([1, 1.4])
            with c_chart:
                fig_av = go.Figure(
                    go.Pie(
                        labels=["Flipped Bits", "Unchanged Bits"],
                        values=[av["flipped_bits"], av["unchanged_bits"]],
                        hole=0.55,
                        marker_colors=["#EF4444", "#1E293B"],
                    )
                )
                fig_av.update_layout(
                    title="256-Bit Digest Avalanche Distribution",
                    height=240,
                    margin=dict(l=10, r=10, t=40, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    font={"color": "#F1F5F9"},
                )
                st.plotly_chart(fig_av, use_container_width=True)

            with c_hex:
                st.markdown("**Byte-Level Hexadecimal & Binary Diff:**")
                st.dataframe(pd.DataFrame(diffs), use_container_width=True, hide_index=True)

# ==============================================================================
# TAB 2: EMAIL & PHISHING FORENSICS (.EML THREAT INSPECTOR)
# ==============================================================================
with tab2:
    st.subheader("RFC-5322 Email Header, Authentication & Phishing Forensics")
    st.write(
        "Upload any exported `.eml` email message to verify **SPF / DKIM / DMARC** alignment, trace **SMTP server hops**, and inspect **URLs & attachment SHA-256 hashes**."
    )

    src_col1, src_col2 = st.columns([1.4, 1])

    with src_col1:
        eml_upload = st.file_uploader(
            "Upload raw email file (.eml)",
            type=["eml"],
            key="eml_file_uploader",
            help="In Gmail or Outlook, open any email -> More (⋮) -> Download message (.eml).",
        )

    with src_col2:
        st.markdown("**Or load a forensic sample artifact:**")
        b_sample1, b_sample2 = st.columns(2)
        load_legit = b_sample1.button("Sample: Valid Security Alert", use_container_width=True)
        load_phish = b_sample2.button("Sample: Spoofed Invoice", use_container_width=True)

    target_eml_bytes = None
    target_eml_name = None

    if eml_upload is not None:
        target_eml_bytes = eml_upload.getvalue()
        target_eml_name = eml_upload.name
    elif load_legit:
        sample_path = os.path.join("sample_emails", "legitimate_security_notice.eml")
        with open(sample_path, "rb") as f:
            target_eml_bytes = f.read()
        target_eml_name = "legitimate_security_notice.eml"
    elif load_phish:
        sample_path = os.path.join("sample_emails", "suspected_phishing_invoice.eml")
        with open(sample_path, "rb") as f:
            target_eml_bytes = f.read()
        target_eml_name = "suspected_phishing_invoice.eml"

    if target_eml_bytes and target_eml_name:
        report = analyze_eml_bytes(target_eml_bytes, target_eml_name)
        st.session_state["active_email_report"] = report

        # Record unique analysis in session history
        if not any(r["eml_sha256"] == report["eml_sha256"] for r in st.session_state["email_history"]):
            st.session_state["email_history"].insert(0, report)

    if "active_email_report" in st.session_state:
        rep = st.session_state["active_email_report"]
        hdr = rep["headers"]
        auth = rep["auth"]
        score = rep["risk_score"]
        verdict = rep["verdict"]

        st.divider()

        # Verdict Banner
        if score >= 65:
            st.markdown(f'<div class="verdict-danger">VERDICT: {verdict} — Risk Score: {score} / 100</div>', unsafe_allow_html=True)
        elif score >= 35:
            st.markdown(f'<div class="verdict-warn">VERDICT: {verdict} — Risk Score: {score} / 100</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="verdict-clean">VERDICT: {verdict} — Risk Score: {score} / 100</div>', unsafe_allow_html=True)

        st.write("")

        # Top Authentication & Artifact KPIs
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("SPF Alignment", auth["spf"])
        k2.metric("DKIM Signature", auth["dkim"])
        k3.metric("DMARC Policy", auth["dmarc"])
        k4.metric("Extracted IOCs", f"{len(rep['urls'])} URLs", f"{len(rep['attachments'])} Attachments")

        left_ev, right_ev = st.columns([1, 1.85])

        with left_ev:
            fig_risk = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=score,
                    title={"text": "Phishing Risk Score"},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "#EF4444" if score >= 65 else ("#F59E0B" if score >= 35 else "#10B981")},
                        "steps": [
                            {"range": [0, 35], "color": "#064E3B"},
                            {"range": [35, 65], "color": "#451A03"},
                            {"range": [65, 100], "color": "#450A0A"},
                        ],
                    },
                )
            )
            fig_risk.update_layout(
                height=240,
                margin=dict(l=15, r=15, t=40, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": "#F1F5F9"},
            )
            st.plotly_chart(fig_risk, use_container_width=True)

            st.markdown("#### Envelope & Header Identity")
            identity_rows = [
                {"Field": "Subject", "Value": hdr["subject"]},
                {"Field": "From (Display)", "Value": hdr["from_display"]},
                {"Field": "From (Address)", "Value": hdr["from_address"]},
                {"Field": "Reply-To", "Value": hdr["reply_to"]},
                {"Field": "Return-Path", "Value": hdr["return_path"]},
                {"Field": "Date", "Value": hdr["date"]},
                {"Field": "Artifact SHA-256", "Value": rep["eml_sha256"][:24] + "..."},
            ]
            st.dataframe(pd.DataFrame(identity_rows), use_container_width=True, hide_index=True)

        with right_ev:
            st.markdown("#### Forensic Findings & Threat Indicators")
            if rep["indicators"]:
                for ind in rep["indicators"]:
                    if score >= 65:
                        st.error(ind)
                    else:
                        st.warning(ind)
            else:
                st.success("No spoofing, authentication failure, or malicious URL/attachment indicators detected.")

            st.markdown("#### Mail Server Routing Trace (Origin → Destination)")
            if rep["hops"]:
                st.dataframe(pd.DataFrame(rep["hops"]), use_container_width=True, hide_index=True)
            else:
                st.info("No 'Received' routing headers present in this message.")

        # URL & Attachment Forensics Row
        st.markdown("#### Extracted URLs & Domain Analysis")
        if rep["urls"]:
            df_urls = pd.DataFrame(rep["urls"])[["Scheme", "Domain", "Forensic Flags", "URL"]]
            st.dataframe(df_urls, use_container_width=True, hide_index=True)
        else:
            st.info("No hyperlinks found in message body.")

        st.markdown("#### Attachment Hashes & Extension Triage")
        if rep["attachments"]:
            st.dataframe(pd.DataFrame(rep["attachments"]), use_container_width=True, hide_index=True)
        else:
            st.info("No file attachments present in this message.")

        with st.expander("View Raw RFC-5322 Message Headers"):
            st.code(rep["raw_headers_text"], language="text")
