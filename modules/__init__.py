"""SentinelScope — File Integrity & Email Threat Forensics Core Modules."""

from .integrity_engine import (
    compute_sha256,
    create_batch_baseline,
    verify_batch_files,
    calculate_avalanche_metrics,
    extract_byte_diff,
)
from .email_forensics import analyze_eml_bytes
from .report_generator import build_html_audit_report

__all__ = [
    "compute_sha256",
    "create_batch_baseline",
    "verify_batch_files",
    "calculate_avalanche_metrics",
    "extract_byte_diff",
    "analyze_eml_bytes",
    "build_html_audit_report",
]
