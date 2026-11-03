"""Metadata, EXIF, and Ghost Thumbnail Discrepancy steganalysis."""

from __future__ import annotations

import base64
import io
import os
import re
import struct
import zlib
from typing import Any, Optional

import numpy as np
from PIL import ExifTags, Image

STANDARD_PNG_CHUNKS = {
    "IHDR", "PLTE", "IDAT", "IEND", "cHRM", "gAMA", "iCCP",
    "sBIT", "sRGB", "bKGD", "hIST", "tRNS", "pHYs", "sPLT",
    "tIME", "iTXt", "tEXt", "zTXt", "eXIf",
}


def _check_suspicious_payload(val_str: str) -> Optional[str]:
    """Test if string contains Base64, Hex payload, or flag pattern."""
    val_clean = val_str.strip()
    if not val_clean:
        return None

    # Flag pattern (FLAG{...}, CTF{...}, etc.)
    flag_match = re.search(r"(?:FLAG|CTF|KEY|SECRET)\{[^}]+\}", val_clean, re.IGNORECASE)
    if flag_match:
        return f"Flag pattern found: '{flag_match.group(0)}'"

    # Hex payload (length >= 24, all hex chars)
    if len(val_clean) >= 24 and re.fullmatch(r"[0-9a-fA-F]+", val_clean):
        try:
            decoded = bytes.fromhex(val_clean)
            if any(32 <= b < 127 for b in decoded):
                return f"Hex encoded data detected: {val_clean[:32]}..."
        except Exception:
            pass

    # Base64 payload (length >= 20, valid b64 chars)
    if len(val_clean) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=]+", val_clean):
        try:
            decoded = base64.b64decode(val_clean, validate=True)
            if len(decoded) >= 12 and any(32 <= b < 127 for b in decoded):
                return f"Base64 encoded payload detected: {val_clean[:32]}..."
        except Exception:
            pass

    return None


def parse_png_chunks(raw_bytes: bytes) -> dict:
    """Parse PNG chunks, decompresses zTXt/tEXt/iTXt, and flags non-standard chunks."""
    if len(raw_bytes) < 8 or raw_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        return {"is_png": False, "chunks": [], "suspicious": False, "reasons": []}

    chunks: list[dict] = []
    reasons: list[str] = []
    suspicious = False
    pos = 8
    total_len = len(raw_bytes)

    while pos + 12 <= total_len:
        length = struct.unpack_from(">I", raw_bytes, pos)[0]
        chunk_type = raw_bytes[pos + 4 : pos + 8].decode("latin-1", errors="replace")
        data = raw_bytes[pos + 8 : pos + 8 + length]

        chunk_info = {"type": chunk_type, "length": length, "offset": pos}

        if chunk_type not in STANDARD_PNG_CHUNKS:
            suspicious = True
            reasons.append(f"Custom/Non-standard PNG chunk '{chunk_type}' ({length} bytes) at offset {pos}")
            # Try preview
            preview = data[:64].decode("latin-1", errors="replace")
            chunk_info["preview"] = preview

        elif chunk_type in ("tEXt", "zTXt", "iTXt"):
            try:
                if chunk_type == "tEXt":
                    parts = data.split(b"\x00", 1)
                    key = parts[0].decode("latin-1", errors="replace")
                    val = parts[1].decode("latin-1", errors="replace") if len(parts) > 1 else ""
                elif chunk_type == "zTXt":
                    parts = data.split(b"\x00", 2)
                    key = parts[0].decode("latin-1", errors="replace")
                    compressed = parts[1][1:] if len(parts) > 1 and len(parts[1]) > 0 else (parts[2] if len(parts) > 2 else b"")
                    val = zlib.decompress(compressed).decode("latin-1", errors="replace")
                else:  # iTXt
                    parts = data.split(b"\x00", 4)
                    key = parts[0].decode("utf-8", errors="replace")
                    val = parts[-1].decode("utf-8", errors="replace") if len(parts) > 4 else ""

                chunk_info["keyword"] = key
                chunk_info["text"] = val[:200]
                susp = _check_suspicious_payload(val)
                if susp:
                    suspicious = True
                    reasons.append(f"Suspicious payload in PNG text chunk '{key}': {susp}")
            except Exception:
                pass

        chunks.append(chunk_info)
        pos += 12 + length

    return {
        "is_png": True,
        "chunks": chunks,
        "suspicious": suspicious,
        "reasons": reasons,
    }


def analyze_metadata(image_path: str) -> dict:
    """Analyze EXIF metadata, PNG chunks, and Ghost Thumbnail discrepancies.

    Returns dict with findings, tags, embedded thumbnails, and suspicious verdict.
    """
    reasons: list[str] = []
    suspicious = False
    exif_data: dict[str, Any] = {}
    has_exif = False
    has_ghost_thumbnail = False
    thumbnail_discrepancy_score = 0.0

    with open(image_path, "rb") as f:
        raw_bytes = f.read()

    # 1. PNG chunk inspection
    png_result = parse_png_chunks(raw_bytes)
    if png_result["is_png"]:
        if png_result["suspicious"]:
            suspicious = True
            reasons.extend(png_result["reasons"])

    # 2. EXIF metadata extraction
    try:
        img = Image.open(image_path)
        exif = img.getexif()
        if exif:
            has_exif = True
            for tag_id, val in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04X}")
                val_str = str(val)
                exif_data[tag_name] = val_str[:150]

                # Check if tag holds hidden payload
                susp = _check_suspicious_payload(val_str)
                if susp:
                    suspicious = True
                    reasons.append(f"EXIF tag '{tag_name}': {susp}")

        # 3. Ghost Thumbnail Discrepancy
        # Look for secondary embedded JPEG inside raw image bytes (EXIF thumbnail)
        soi_indices = [m.start() for m in re.finditer(b"\xff\xd8", raw_bytes)]
        if len(soi_indices) > 1:
            thumb_start = soi_indices[1]
            eoi_match = raw_bytes.find(b"\xff\xd9", thumb_start)
            if eoi_match != -1 and (eoi_match - thumb_start) > 64:
                thumb_bytes = raw_bytes[thumb_start : eoi_match + 2]
                try:
                    thumb_img = Image.open(io.BytesIO(thumb_bytes)).convert("L")
                    main_img_down = img.convert("L").resize(thumb_img.size, Image.Resampling.BILINEAR)

                    arr_thumb = np.array(thumb_img, dtype=np.float64)
                    arr_main = np.array(main_img_down, dtype=np.float64)

                    # Normalized Mean Absolute Error
                    diff = np.mean(np.abs(arr_thumb - arr_main)) / 255.0
                    thumbnail_discrepancy_score = round(float(diff), 4)

                    if diff > 0.20:
                        suspicious = True
                        has_ghost_thumbnail = True
                        reasons.append(
                            f"Ghost Thumbnail Discrepancy detected (diff={diff:.2%}): "
                            "embedded EXIF thumbnail significantly diverges from displayed image"
                        )
                except Exception:
                    pass

    except Exception:
        pass

    return {
        "has_exif": has_exif,
        "exif_tags": exif_data,
        "is_png": png_result["is_png"],
        "png_chunks_count": len(png_result.get("chunks", [])),
        "has_ghost_thumbnail": has_ghost_thumbnail,
        "thumbnail_discrepancy_score": thumbnail_discrepancy_score,
        "suspicious": suspicious,
        "reasons": reasons,
    }
