# SentinelScope — File Integrity & Email Threat Forensics Platform

**SentinelScope** is a modular Security Operations and Digital Forensics web application built with **Python**, **Streamlit**, and **Plotly**.

## Core Capabilities

1. **Cryptographic File Integrity Monitor**
   - Generates multi-file **SHA-256** cryptographic baselines and detects unauthorized file modifications.
   - Computes exact bit-level **Hamming Distance** across 256-bit digests to verify cryptographic avalanche behavior (~50% bit flip on a 1-bit input change).
   - Displays byte-level **Hexadecimal and Binary** forensic diffs for modified files.

2. **RFC-5322 Email & Phishing Forensics Inspector (`.eml`)**
   - Evaluates **SPF**, **DKIM**, and **DMARC** authentication verdicts and flags `From` / `Return-Path` / `Reply-To` spoofing mismatches.
   - Reconstructs chronological **SMTP mail-server routing hops** with IP extraction and transit delay calculation.
   - Scans plain-text and HTML bodies for **IDN Homograph/Punycode domains**, **IP-literal links**, **Href-Text masking**, and computes **SHA-256 hashes** for all attachments.

3. **Compliance Audit Export**
   - Generates a downloadable standalone HTML audit report consolidating file integrity results and email forensic investigations.

## Directory Layout

```text
SentinelScope/
├── app.py
├── requirements.txt
├── README.md
├── .streamlit/
│   └── config.toml
├── sample_emails/
│   ├── legitimate_security_notice.eml
│   └── suspected_phishing_invoice.eml
└── modules/
    ├── __init__.py
    ├── integrity_engine.py
    ├── email_forensics.py
    └── report_generator.py
```

## Quick Start

```bash
cd SentinelScope
pip install -r requirements.txt
streamlit run app.py
```
