"""JPEG DCT frequency domain analysis — detect JSteg, OutGuess, F5, and marker anomalies."""

from __future__ import annotations

import math
import os
from collections import Counter
from typing import Optional

import numpy as np
from PIL import Image

from .common import entropy
from .lsb import _chi2_cdf

# Standard JPEG Luminance Quantization Table (50% quality baseline)
STD_LUM_QTABLE = np.array([
    [16, 11, 10, 16, 24, 40, 51, 61],
    [12, 12, 14, 19, 26, 58, 60, 55],
    [14, 13, 16, 24, 40, 57, 69, 56],
    [14, 17, 22, 29, 51, 87, 80, 62],
    [18, 22, 37, 56, 68, 109, 103, 77],
    [24, 35, 55, 64, 81, 104, 113, 92],
    [49, 64, 78, 87, 103, 121, 120, 101],
    [72, 92, 95, 98, 112, 100, 103, 99],
], dtype=np.float64)

# 8x8 Orthonormal DCT transformation matrix
_DCT_BASIS = np.zeros((8, 8), dtype=np.float64)
for _i in range(8):
    for _j in range(8):
        if _i == 0:
            _DCT_BASIS[_i, _j] = 1.0 / np.sqrt(8.0)
        else:
            _DCT_BASIS[_i, _j] = np.sqrt(2.0 / 8.0) * np.cos((2 * _j + 1) * _i * np.pi / 16.0)


def parse_jpeg_markers(raw_bytes: bytes) -> dict:
    """Parse JPEG structure, markers, comments, quantization tables, and trailing bytes."""
    if len(raw_bytes) < 4 or raw_bytes[:2] != b"\xff\xd8":
        return {
            "is_jpeg": False,
            "markers": [],
            "comments": [],
            "has_dqt": False,
            "q_tables": [],
            "eoi_offset": -1,
            "trailing_bytes": 0,
        }

    markers: list[dict] = []
    comments: list[str] = []
    q_tables: list[np.ndarray] = []
    eoi_offset = -1
    pos = 2
    data_len = len(raw_bytes)

    while pos < data_len - 1:
        if raw_bytes[pos] != 0xFF:
            # Resync or invalid byte
            pos += 1
            continue

        marker = raw_bytes[pos + 1]
        # Skip fill bytes 0xFF 0xFF
        if marker == 0xFF or marker == 0x00:
            pos += 1
            continue

        # EOI (End of Image)
        if marker == 0xD9:
            eoi_offset = pos + 2
            markers.append({"marker": "EOI", "hex": "0xFFD9", "offset": pos, "length": 0})
            break

        # Standalone markers without length: SOI, TEM, RST0-RST7
        if marker in (0xD8, 0x01) or (0xD0 <= marker <= 0xD7):
            markers.append({"marker": f"0xFF{marker:02X}", "hex": f"0xFF{marker:02X}", "offset": pos, "length": 0})
            pos += 2
            continue

        if pos + 4 > data_len:
            break

        segment_length = int.from_bytes(raw_bytes[pos + 2 : pos + 4], "big")
        marker_name = f"0xFF{marker:02X}"
        payload = raw_bytes[pos + 4 : pos + 2 + segment_length]

        if marker == 0xFE:  # COM (Comment)
            marker_name = "COM"
            try:
                comments.append(payload.decode("utf-8", errors="replace"))
            except Exception:
                pass
        elif marker == 0xDB:  # DQT (Quantization Table)
            marker_name = "DQT"
            # Parse 64-byte quantization table(s)
            q_pos = 0
            while q_pos < len(payload):
                info = payload[q_pos]
                precision = (info >> 4) & 0x0F
                q_pos += 1
                table_size = 128 if precision == 1 else 64
                if q_pos + table_size <= len(payload):
                    t_bytes = payload[q_pos : q_pos + table_size]
                    if precision == 1:
                        table = [int.from_bytes(t_bytes[k : k + 2], "big") for k in range(0, 128, 2)]
                    else:
                        table = list(t_bytes)
                    if len(table) == 64:
                        q_tables.append(np.array(table, dtype=np.float64).reshape((8, 8)))
                    q_pos += table_size
                else:
                    break
        elif marker == 0xC0:
            marker_name = "SOF0 (Baseline)"
        elif marker == 0xC2:
            marker_name = "SOF2 (Progressive)"
        elif marker == 0xC4:
            marker_name = "DHT (Huffman)"
        elif marker == 0xDA:
            marker_name = "SOS (Scan)"

        markers.append({
            "marker": marker_name,
            "hex": f"0xFF{marker:02X}",
            "offset": pos,
            "length": segment_length,
        })

        if marker == 0xDA:  # SOS: entropy coded stream follows
            pos += 2 + segment_length
            while pos < data_len - 1:
                if raw_bytes[pos] == 0xFF:
                    next_b = raw_bytes[pos + 1]
                    if next_b != 0x00 and not (0xD0 <= next_b <= 0xD7) and next_b != 0xFF:
                        # Found next real marker
                        break
                pos += 1
            continue

        pos += 2 + segment_length

    trailing = max(0, data_len - eoi_offset) if eoi_offset != -1 else 0

    return {
        "is_jpeg": True,
        "markers": markers,
        "comments": comments,
        "has_dqt": len(q_tables) > 0,
        "q_tables": q_tables,
        "eoi_offset": eoi_offset,
        "trailing_bytes": trailing,
    }


def compute_block_dct(gray_pixels: np.ndarray) -> np.ndarray:
    """Compute 8x8 block 2D Discrete Cosine Transform across an image array."""
    h, w = gray_pixels.shape
    # Pad to multiple of 8
    pad_h = (8 - (h % 8)) % 8
    pad_w = (8 - (w % 8)) % 8
    if pad_h > 0 or pad_w > 0:
        gray_pixels = np.pad(gray_pixels, ((0, pad_h), (0, pad_w)), mode="edge")

    h_pad, w_pad = gray_pixels.shape
    n_blocks_h = h_pad // 8
    n_blocks_w = w_pad // 8

    # Extract 8x8 blocks: shape (n_blocks_h, n_blocks_w, 8, 8)
    blocks = (
        gray_pixels.reshape(n_blocks_h, 8, n_blocks_w, 8)
        .transpose(0, 2, 1, 3)
        .astype(np.float64)
        - 128.0
    )

    # 2D DCT: D = A @ blocks @ A.T
    dct_blocks = _DCT_BASIS @ blocks @ _DCT_BASIS.T
    return dct_blocks


def westfeld_chi_square_jsteg(ac_coeffs: np.ndarray) -> tuple[float, float, int]:
    """Westfeld Chi-Square test for JSteg detection on Pairs of Values (PoVs).

    JSteg embeds bits into the LSB of AC coefficients, equalizing pairs:
    (2k, 2k+1) and (-2k-1, -2k).
    In clean images, p is near 0.0 (asymmetric pairs).
    In JSteg-embedded images, p approaches 1.0 (equalized pairs).

    Returns: (chi2_statistic, p_value, active_pairs_count)
    """
    counts = Counter(ac_coeffs.tolist())

    chi2 = 0.0
    active_pairs = 0

    # Test positive pairs: (2, 3), (4, 5), (6, 7)... up to 64
    for k in range(1, 32):
        v1, v2 = 2 * k, 2 * k + 1
        n1 = counts.get(v1, 0)
        n2 = counts.get(v2, 0)
        total = n1 + n2
        if total >= 5:
            # Pair has enough samples for chi-square
            chi2 += ((n1 - n2) ** 2) / total
            active_pairs += 1

    # Test negative pairs: (-3, -2), (-5, -4)...
    for k in range(1, 32):
        v1, v2 = -(2 * k + 1), -(2 * k)
        n1 = counts.get(v1, 0)
        n2 = counts.get(v2, 0)
        total = n1 + n2
        if total >= 5:
            chi2 += ((n1 - n2) ** 2) / total
            active_pairs += 1

    if active_pairs <= 1:
        return 0.0, 0.0, 0

    df = active_pairs - 1
    p = 1.0 - _chi2_cdf(chi2, df)
    return chi2, p, active_pairs


def compute_blockiness_metric(gray_pixels: np.ndarray) -> float:
    """Measure inter-block vs intra-block boundary discontinuity (OutGuess detection)."""
    h, w = gray_pixels.shape
    if h < 16 or w < 16:
        return 1.0

    # Horizontal boundary difference: across 8x8 boundaries (row 7 vs row 8, etc.)
    inter_diffs = []
    intra_diffs = []

    for r in range(1, h):
        diff = np.mean(np.abs(gray_pixels[r, :] - gray_pixels[r - 1, :]))
        if r % 8 == 0:
            inter_diffs.append(diff)
        else:
            intra_diffs.append(diff)

    inter_mean = float(np.mean(inter_diffs)) if inter_diffs else 0.0
    intra_mean = float(np.mean(intra_diffs)) if intra_diffs else 1.0

    return inter_mean / (intra_mean + 1e-6)


def analyze_jpeg_dct(image_path: str) -> dict:
    """Perform DCT frequency domain and marker steganalysis on a JPEG or image file.

    Evaluates:
      1. Westfeld Chi-Square on Pairs of Values (PoVs) for JSteg detection.
      2. F5 histogram shrinkage and zero-bin inflation.
      3. OutGuess inter-block boundary discontinuity.
      4. AC coefficient LSB entropy and 0/1 bit distribution.
      5. Structural JPEG marker anomalies, hidden comments, and trailing data.

    Returns dict with metrics and suspicious verdict.
    """
    reasons: list[str] = []
    suspicious = False

    # Read binary bytes for JPEG marker and structure analysis
    with open(image_path, "rb") as f:
        raw_bytes = f.read()

    structure = parse_jpeg_markers(raw_bytes)
    is_jpeg = structure["is_jpeg"]

    # Load image for DCT computation
    img = Image.open(image_path).convert("L")
    gray = np.array(img, dtype=np.float64)

    # Compute block DCT
    dct_blocks = compute_block_dct(gray)

    # Use parsed quantization table if available, else standard luminance table
    q_table = structure["q_tables"][0] if structure["q_tables"] else STD_LUM_QTABLE
    quantized_blocks = np.round(dct_blocks / q_table).astype(int)

    # Separate DC (0,0) and AC (all other 63 positions) coefficients
    # quantized_blocks shape: (n_blocks_h, n_blocks_w, 8, 8)
    ac_mask = np.ones((8, 8), dtype=bool)
    ac_mask[0, 0] = False
    ac_coeffs = quantized_blocks[:, :, ac_mask].flatten()

    total_ac = len(ac_coeffs)
    zero_ac = int(np.sum(ac_coeffs == 0))
    non_zero_ac = ac_coeffs[ac_coeffs != 0]
    non_zero_count = len(non_zero_ac)

    # Test 1: JSteg Westfeld Chi-Square test
    chi2_stat, jsteg_p, active_pairs = westfeld_chi_square_jsteg(ac_coeffs)
    jsteg_detected = False
    if active_pairs >= 4 and jsteg_p > 0.85:
        jsteg_detected = True
        suspicious = True
        reasons.append(
            f"JSteg detected: DCT pairs equalized (chi2={chi2_stat:.2f}, p={jsteg_p:.4f}, pairs={active_pairs})"
        )

    # Test 2: F5 Shrinkage & Zero-inflation analysis
    f5_detected = False
    f5_zero_ratio = (zero_ac / total_ac) if total_ac > 0 else 0.0
    c_plus1 = int(np.sum(ac_coeffs == 1))
    c_minus1 = int(np.sum(ac_coeffs == -1))
    sum_ones = c_plus1 + c_minus1
    zero_to_ones_ratio = (zero_ac / sum_ones) if sum_ones > 0 else 0.0

    # In images with sufficient AC density (at least 250 non-zero ACs), F5 matrix embedding
    # shrinks coefficients towards zero, causing abnormal zero inflation relative to ones.
    if non_zero_count >= 250 and total_ac > 1000 and f5_zero_ratio > 0.92 and zero_to_ones_ratio > 35.0:
        f5_detected = True
        suspicious = True
        reasons.append(
            f"F5 shrinkage anomaly: abnormal zero-bin inflation ({f5_zero_ratio:.2%} zero ACs, ratio={zero_to_ones_ratio:.1f})"
        )

    # Test 3: Blockiness metric (OutGuess block artifact disruption)
    blockiness = compute_blockiness_metric(gray)
    outguess_anomaly = False
    if blockiness > 1.45:
        outguess_anomaly = True
        suspicious = True
        reasons.append(f"Elevated block boundary discontinuity (blockiness={blockiness:.3f})")

    # Test 4: AC LSB entropy and bit balance
    ac_lsb_entropy = 0.0
    ac_lsb_ratio = 0.0
    if non_zero_count > 100:
        lsb_bits = [abs(int(c)) & 1 for c in non_zero_ac]
        ac_lsb_entropy = entropy(bytes(lsb_bits))
        ac_lsb_ratio = sum(lsb_bits) / len(lsb_bits)
        if ac_lsb_entropy > 0.995 and 0.48 <= ac_lsb_ratio <= 0.52 and non_zero_count > 500:
            if not jsteg_detected:  # complement if not already flagged
                suspicious = True
                reasons.append(
                    f"Near-perfect AC coefficient LSB randomness (entropy={ac_lsb_entropy:.4f}, ratio={ac_lsb_ratio:.4f})"
                )

    # Test 5: JPEG structure & marker anomalies
    if structure["comments"]:
        suspicious = True
        reasons.append(f"Embedded JPEG comment(s) found: {structure['comments']}")

    if structure["trailing_bytes"] > 0:
        suspicious = True
        reasons.append(f"{structure['trailing_bytes']} trailing bytes detected past EOI marker")

    return {
        "is_jpeg": is_jpeg,
        "suspicious": suspicious,
        "reasons": reasons,
        "jsteg_detected": jsteg_detected,
        "jsteg_p_value": round(jsteg_p, 6),
        "f5_detected": f5_detected,
        "f5_zero_ratio": round(f5_zero_ratio, 4),
        "blockiness": round(blockiness, 4),
        "ac_lsb_entropy": round(ac_lsb_entropy, 4),
        "ac_lsb_ratio": round(ac_lsb_ratio, 4),
        "total_ac_coefficients": total_ac,
        "non_zero_ac_count": non_zero_count,
        "comments": structure["comments"],
        "trailing_bytes": structure["trailing_bytes"],
    }
