"""LSB steganography analysis — bit-plane extraction, distribution tests, chi-square."""

from __future__ import annotations

import math
from collections import Counter
from typing import Optional

from .common import entropy


def _get_lsb_plane(pixels: list[int], bit: int = 0) -> bytes:
    """Extract one bit-plane from a flat list of pixel values."""
    return bytes((p >> bit) & 1 for p in pixels)


def _get_lsb_bytes(pixels: list[int], bits_per_sample: int = 1) -> bytes:
    """Collect LSBs from consecutive pixels into bytes (MSB-first)."""
    bits: list[int] = []
    for p in pixels:
        for b in range(bits_per_sample):
            bits.append((p >> b) & 1)
    # Pad to full byte
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


def _chi_square_uniform(observed: list[int]) -> tuple[float, float]:
    """Chi-square test against uniform distribution.
    Returns (chi2_stat, p_value). Low p → likely hidden data.
    """
    n = sum(observed)
    if n == 0:
        return 0.0, 1.0
    expected = n / len(observed)
    chi2 = sum((o - expected) ** 2 / expected for o in observed if expected > 0)
    # Degrees of freedom = len(observed) - 1
    k = len(observed) - 1
    if k <= 0 or chi2 < 0:
        return 0.0, 1.0
    # Regularized lower incomplete gamma for chi-square CDF
    p = _chi2_cdf(chi2, k)
    return chi2, 1.0 - p


def _chi2_cdf(x: float, k: int) -> float:
    """Chi-square CDF using the regularized lower incomplete gamma function.
    (Lanczos approximation, accurate enough for our use.)
    """
    from math import exp, lgamma, log

    if x <= 0 or k <= 0:
        return 0.0
    a = k / 2.0
    return _reg_lower_gamma(a, x / 2.0)


def _reg_lower_gamma(a: float, x: float, iterations: int = 200) -> float:
    """Regularized lower incomplete gamma P(a,x).

    Uses the series expansion when x <= a+1 and the Lentz continued fraction
    for the upper incomplete gamma when x > a+1 (where the series diverges).
    Numerically stable for the chi-square CDF.
    """
    from math import exp, lgamma, log

    if x < 0 or a <= 0:
        return 0.0
    if x == 0:
        return 0.0

    ln_gamma_a = lgamma(a)

    if x < a + 1.0:
        # Series: P(a,x) = e^-x * x^a / gamma(a) * sum(x^n / gamma(a+1+n))
        s = 1.0 / a
        t = 1.0 / a
        for n in range(1, iterations):
            t *= x / (a + n)
            s += t
            if abs(t) < abs(s) * 1e-15:
                break
        return exp(a * log(x) - x - ln_gamma_a) * s

    # Continued fraction: Q(a,x) = 1 - P(a,x) = gamma(a,x)/gamma(a)
    #   gamma(a,x) = e^-x * x^a * 1/(x+1-a - 1*(1-a)/(x+3-a - 2*(2-a)/(...)))
    # Use the Lentz method on the standard continued fraction for Q.
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b if b != 0 else tiny
    h = d
    for i in range(1, iterations + 1):
        an = -i * (i - a)
        b = b + 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    q = exp(a * log(x) - x - ln_gamma_a) * h
    return max(0.0, min(1.0, 1.0 - q))


def analyze_lsb(image_path: str) -> dict:
    """Analyze LSB planes for signs of hidden data.

    Detection signals:
      1. A plausible 4-byte message-length prefix in the LSB stream whose
         following bytes are printable ASCII (strong signal).
      2. Low entropy in the LSB bit-plane (natural images have ~1.0).
      3. Chi-square rejecting a uniform 2-bit pair distribution.

    Returns a dict with:
      - ``suspicious``: bool
      - ``reasons``: list of human-readable findings
      - ``planes``: per-bit-plane stats (bit 0 is the true LSB)
      - ``recomputed_message_length``: estimated message length in bytes
      - ``chi_square_p_value``: p-value for LSB pair uniformity
    """
    from PIL import Image

    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    pixels = list(img.get_flattened_data())

    channels = {
        "R": [p[0] for p in pixels],
        "G": [p[1] for p in pixels],
        "B": [p[2] for p in pixels],
    }

    # --- Per-channel bit-plane stats ---
    plane_results: dict[str, dict[int, dict]] = {}
    for ch_name, ch_vals in channels.items():
        plane_results[ch_name] = {}
        for bit in range(8):
            bits = _get_lsb_plane(ch_vals, bit)
            ent = entropy(bits)
            count_1 = bits.count(1)
            ratio = count_1 / len(bits) if bits else 0
            pairs = [bits[i] * 2 + bits[i + 1] for i in range(0, len(bits) - 1, 2)]
            hist = [0] * 4
            for v in pairs:
                hist[v] += 1
            chi2, p = _chi_square_uniform(hist)
            plane_results[ch_name][bit] = {
                "entropy": round(ent, 4),
                "ratio_1": round(ratio, 4),
                "chi_square_p": round(p, 6),
            }

    # --- Reconstruct LSB stream (R,G,B,R,G,B,... sequential) ---
    flat = [v for p in pixels for v in p]
    raw_bytes = _get_lsb_bytes(flat, bits_per_sample=1)

    # Signal 1: length prefix + ASCII content
    msg_len: Optional[int] = None
    length_plausible = False
    ascii_content = False
    if len(raw_bytes) >= 4:
        candidate_len = int.from_bytes(raw_bytes[:4], "big")
        max_plausible = min(len(raw_bytes) - 4, 100_000)
        if 0 < candidate_len < max_plausible:
            msg_len = candidate_len
            window = raw_bytes[4:4 + candidate_len]
            if window:
                printable = sum(32 <= b < 127 for b in window) / len(window)
                ascii_content = printable > 0.7
                length_plausible = True

    # Signal 2: LSB entropy (true LSB = bit 0)
    lsb_bits = [v & 1 for v in flat]
    lsb_ent = entropy(bytes(lsb_bits))
    # Signal 3: chi-square on LSB pairs
    lsb_pairs = [lsb_bits[i] * 2 + lsb_bits[i + 1] for i in range(0, len(lsb_bits) - 1, 2)]
    lsb_hist = [0] * 4
    for v in lsb_pairs:
        lsb_hist[v] += 1
    lsb_chi2, lsb_p = _chi_square_uniform(lsb_hist)

    # Control: MSB (bit 7) entropy — natural images have structured MSB
    msb_bits = [(v >> 7) & 1 for v in flat]
    msb_ent = entropy(bytes(msb_bits))

    # --- Verdict ---
    reasons: list[str] = []
    suspicious = False

    if length_plausible and ascii_content:
        suspicious = True
        reasons.append(
            f"LSB stream begins with {msg_len}-byte length prefix followed by ASCII content"
        )
    elif length_plausible:
        # Length prefix exists but content isn't ASCII — still notable
        suspicious = True
        reasons.append(f"LSB stream begins with a {msg_len}-byte length prefix")

    if lsb_ent < 0.85:
        suspicious = True
        reasons.append(f"low LSB entropy ({lsb_ent:.3f}) — plane too structured")

    if lsb_p < 0.0001:
        suspicious = True
        reasons.append(f"chi-square rejects uniform LSB pairs (p={lsb_p:.5f})")

    return {
        "suspicious": suspicious,
        "reasons": reasons,
        "planes": plane_results,
        "lsb_entropy": round(lsb_ent, 4),
        "msb_entropy": round(msb_ent, 4),
        "recomputed_message_length": msg_len,
        "chi_square_p_value": round(lsb_p, 6),
        "image_size": (width, height),
        "total_pixels": width * height,
    }