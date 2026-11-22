"""Cryptographic File Integrity Engine with Batch Scanning, Bit-Flip Avalanche & Hex Diff."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone


def compute_sha256(data: bytes) -> str:
    """Return lowercase 64-char SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def create_batch_baseline(file_items: list[tuple[str, bytes]], label: str = "Batch Baseline") -> dict:
    """Create a multi-file SHA-256 baseline manifest."""
    entries = {}
    total_bytes = 0
    for name, content in file_items:
        digest = compute_sha256(content)
        size = len(content)
        total_bytes += size
        entries[name] = {
            "sha256": digest,
            "size_bytes": size,
        }

    return {
        "system": "SentinelScope Integrity Engine",
        "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "label": label.strip() or "Batch Baseline",
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": entries,
    }


def verify_batch_files(manifest: dict, suspect_items: list[tuple[str, bytes]]) -> dict:
    """Verify multiple uploaded files against a baseline manifest."""
    if not isinstance(manifest, dict) or "files" not in manifest:
        raise ValueError("Invalid baseline JSON format. Expected top-level 'files' dictionary.")

    baseline_files = manifest["files"]
    results = []
    verified_count = 0
    tampered_count = 0
    untracked_count = 0

    for name, content in suspect_items:
        actual_hash = compute_sha256(content)
        actual_size = len(content)

        if name not in baseline_files:
            untracked_count += 1
            results.append(
                {
                    "File Name": name,
                    "Status": "UNTRACKED (New File)",
                    "Size (Bytes)": actual_size,
                    "Expected SHA-256": "Not in baseline",
                    "Actual SHA-256": actual_hash,
                    "Avalanche Flip %": 0.0,
                }
            )
            continue

        expected_hash = baseline_files[name]["sha256"].lower().strip()
        is_match = hmac.compare_digest(expected_hash, actual_hash)

        if is_match:
            verified_count += 1
            flip_pct = 0.0
            status = "VERIFIED (Intact)"
        else:
            tampered_count += 1
            av = calculate_avalanche_metrics(expected_hash, actual_hash)
            flip_pct = av["flip_percentage"]
            status = "TAMPERED (Modified)"

        results.append(
            {
                "File Name": name,
                "Status": status,
                "Size (Bytes)": actual_size,
                "Expected SHA-256": expected_hash,
                "Actual SHA-256": actual_hash,
                "Avalanche Flip %": flip_pct,
            }
        )

    total_checked = len(suspect_items)
    integrity_score = round((verified_count / total_checked) * 100, 1) if total_checked > 0 else 0.0

    return {
        "checked_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_checked": total_checked,
        "verified_count": verified_count,
        "tampered_count": tampered_count,
        "untracked_count": untracked_count,
        "integrity_score": integrity_score,
        "records": results,
    }


def calculate_avalanche_metrics(hex_hash_a: str, hex_hash_b: str) -> dict:
    """Calculate exact bit-level Hamming distance between two 256-bit SHA-256 digests."""
    int_a = int(hex_hash_a, 16)
    int_b = int(hex_hash_b, 16)
    xor_val = int_a ^ int_b
    flipped_bits = xor_val.bit_count()
    total_bits = 256
    flip_percentage = round((flipped_bits / total_bits) * 100, 2)
    return {
        "flipped_bits": flipped_bits,
        "unchanged_bits": total_bits - flipped_bits,
        "total_bits": total_bits,
        "flip_percentage": flip_percentage,
    }


def extract_byte_diff(original: bytes, modified: bytes, max_diffs: int = 8) -> list[dict]:
    """Locate byte offsets where two binary payloads differ and show Hex & Binary values."""
    diffs = []
    max_len = max(len(original), len(modified))
    for idx in range(max_len):
        b1 = original[idx] if idx < len(original) else None
        b2 = modified[idx] if idx < len(modified) else None
        if b1 != b2:
            diffs.append(
                {
                    "Byte Offset": f"0x{idx:04X} ({idx})",
                    "Original Hex": f"0x{b1:02X}" if b1 is not None else "EOF",
                    "Modified Hex": f"0x{b2:02X}" if b2 is not None else "EOF",
                    "Original Binary": f"{b1:08b}" if b1 is not None else "--------",
                    "Modified Binary": f"{b2:08b}" if b2 is not None else "--------",
                    "ASCII": f"{chr(b1) if b1 and 32 <= b1 <= 126 else '.'} → {chr(b2) if b2 and 32 <= b2 <= 126 else '.'}",
                }
            )
            if len(diffs) >= max_diffs:
                break
    return diffs
