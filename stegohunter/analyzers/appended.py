"""Appended-data scanner — find data appended after the end-of-file marker in
common image and audio formats."""

from __future__ import annotations

import struct
from typing import Optional

# Format-specific end-of-image markers
EOI_MARKERS: dict[str, bytes] = {
    ".jpg": b"\xff\xd9",       # JPEG EOI
    ".jpeg": b"\xff\xd9",
    ".png": b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82",  # PNG IEND chunk
    ".gif": b"\x00\x3b",       # GIF trailer
    ".bmp": b"",               # BMP — no standard EOI; use file header for size
    ".tiff": b"",              # TIFF — no standard EOI; parse IFD
    ".wav": b"",               # WAV — use RIFF chunk size
    ".mp3": b"",               # MP3 — ID3v1 tag at EOF, otherwise no marker
    ".flac": b"",              # FLAC — use STREAMINFO block size
}


def find_eoi_offset(data: bytes, ext: str) -> int:
    """Find the end-of-image offset for a given format.

    Returns -1 if the format is unknown or the marker is not found.
    """
    marker = EOI_MARKERS.get(ext.lower())
    if not marker:
        return -1
    idx = data.rfind(marker)
    if idx == -1:
        return -1
    return idx + len(marker)


def find_appended_data(path: str) -> dict:
    """Scan file for data appended after the legitimate end of the format.

    Returns a dict with:
      - ``appended``: bool — whether trailing data was found
      - ``offset``: int — byte offset where appended data starts
      - ``size``: int — number of appended bytes
      - ``data``: bytes — the appended data (first 1024 bytes, or all if smaller)
      - ``entropy``: float — Shannon entropy of the trailing data
      - ``contains_zip``: bool — check for PK\x03\x04 magic
      - ``contains_text``: bool — check for printable ASCII strings
    """
    import os

    from .common import entropy

    if not os.path.exists(path):
        return {"appended": False, "error": "File not found"}

    with open(path, "rb") as f:
        data = f.read()

    ext = os.path.splitext(path)[1].lower()

    # --- Determine expected file size ---
    expected_end = -1

    if ext in (".jpg", ".jpeg"):
        # JPEG: find last EOI marker
        expected_end = find_eoi_offset(data, ext)

    elif ext == ".png":
        # PNG: find last IEND chunk
        expected_end = find_eoi_offset(data, ext)

    elif ext == ".gif":
        # GIF: find trailer byte
        expected_end = find_eoi_offset(data, ext)

    elif ext == ".bmp":
        # BMP: size at offset 2 (4 bytes, little-endian)
        if len(data) >= 6:
            expected_end = struct.unpack_from("<I", data, 2)[0]
        else:
            expected_end = len(data)

    elif ext == ".wav":
        # WAV (RIFF): file size at offset 4 (4 bytes, little-endian)
        if len(data) >= 8 and data[:4] == b"RIFF":
            chunk_size = struct.unpack_from("<I", data, 4)[0]
            expected_end = chunk_size + 8  # RIFF size doesn't include 'RIFF' + size field
        else:
            expected_end = len(data)

    elif ext == ".mp3":
        # MP3: ID3v1 tag is 128 bytes at EOF; also check for ID3v2 header
        # If no ID3v1, try to find last valid MP3 frame header
        # Simplistic: just check for ID3v1 tag
        if len(data) > 128 and data[-128:-125] == b"TAG":
            expected_end = len(data) - 128
        else:
            # Try to find APEtag or just use last frame sync
            # Conservative: look for last 0xFFE0+ frame sync
            # Only flag if we find something remarkable
            expected_end = len(data)  # No reliable detection without full parser

    elif ext == ".flac":
        # FLAC: STREAMINFO block tells total samples; rather than full parse,
        # just check for appended data after last metadata block + audio data
        # Conservative: just use file size
        expected_end = len(data)

    elif ext == ".tiff":
        # TIFF: file size from IFD chain — complex; just check for unexpected
        # trailing bytes vs a simplified end calculation
        expected_end = len(data)

    if expected_end == -1 or expected_end >= len(data):
        # No marker found or file ends exactly at expected point
        return {
            "appended": False,
            "offset": expected_end if expected_end != -1 else len(data),
            "size": 0,
            "data": b"",
            "entropy": 0.0,
            "contains_zip": False,
            "contains_text": False,
        }

    # --- Analyze trailing data ---
    trailing = data[expected_end:]
    if not trailing:
        return {
            "appended": False,
            "offset": expected_end,
            "size": 0,
            "data": b"",
            "entropy": 0.0,
            "contains_zip": False,
            "contains_text": False,
        }

    ent = entropy(trailing)
    has_zip = trailing[:2] == b"PK" or b"PK\x03\x04" in trailing[:256]
    has_text = bool(
        any(32 <= b < 127 for b in trailing[:256])
        and sum(32 <= b < 127 for b in trailing[:256]) > len(trailing[:256]) * 0.6
    )

    # Check for known file signatures in trailing data
    signatures: list[tuple[str, bytes]] = [
        ("ZIP", b"PK\x03\x04"),
        ("RAR", b"Rar!\x1a\x07"),
        ("GZIP", b"\x1f\x8b"),
        ("BZ2", b"BZh"),
        ("XZ", b"\xfd7zXZ"),
        ("PDF", b"%PDF"),
        ("PNG", b"\x89PNG"),
        ("JPEG", b"\xff\xd8\xff"),
        ("ELF", b"\x7fELF"),
        ("ZSTD", b"\x28\xb5\x2f\xfd"),
    ]
    found_signatures = []
    for name, magic in signatures:
        if magic in trailing[:4096]:
            found_signatures.append(name)

    return {
        "appended": True,
        "offset": expected_end,
        "size": len(trailing),
        "data": trailing[:1024],  # Preview
        "entropy": round(ent, 4),
        "contains_zip": has_zip,
        "contains_text": has_text,
        "found_signatures": found_signatures,
    }