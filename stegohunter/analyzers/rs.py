"""RS Steganalysis and Sample Pair Analysis (SPA) — mathematical embedding rate estimators."""

from __future__ import annotations

import math
from typing import Optional

import numpy as np
from PIL import Image


def _rs_analyze_channel(channel_2d: np.ndarray) -> tuple[float, dict]:
    """Perform 2x2 block RS Steganalysis (Fridrich et al.) on a single 2D channel array.

    Returns:
      (estimated_rate, details_dict)
    """
    img = np.array(channel_2d, dtype=np.int32)
    h, w = img.shape
    h_blocks = h // 2
    w_blocks = w // 2

    if h_blocks < 2 or w_blocks < 2:
        return 0.0, {"error": "Channel too small for RS analysis"}

    # Extract 2x2 blocks: shape (n_blocks, 4)
    # Block layout: [ (y, x), (y, x+1), (y+1, x), (y+1, x+1) ]
    blocks = (
        img[: h_blocks * 2, : w_blocks * 2]
        .reshape(h_blocks, 2, w_blocks, 2)
        .transpose(0, 2, 1, 3)
        .reshape(-1, 4)
    )

    # Discrimination function: variation across 2x2 group
    # f(G) = |x1 - x2| + |x2 - x4| + |x4 - x3| + |x3 - x1|
    def f_disc(G: np.ndarray) -> np.ndarray:
        return (
            np.abs(G[:, 0] - G[:, 1])
            + np.abs(G[:, 1] - G[:, 3])
            + np.abs(G[:, 3] - G[:, 2])
            + np.abs(G[:, 2] - G[:, 0])
        )

    mask = np.array([0, 1, 1, 0])

    def f_flip(G: np.ndarray, m_val: int) -> np.ndarray:
        G_c = G.copy()
        for i in range(4):
            if mask[i] == 1:
                if m_val == 1:
                    G_c[:, i] ^= 1
                elif m_val == -1:
                    col = G_c[:, i]
                    odds = col % 2 != 0
                    G_c[odds, i] = col[odds] + 1
                    G_c[~odds, i] = col[~odds] - 1
        return G_c

    # Group counts on original image
    f0 = f_disc(blocks)
    f_pos = f_disc(f_flip(blocks, 1))
    f_neg = f_disc(f_flip(blocks, -1))

    r_m = float(np.mean(f_pos > f0))
    s_m = float(np.mean(f_pos < f0))
    r_nm = float(np.mean(f_neg > f0))
    s_nm = float(np.mean(f_neg < f0))

    # Group counts on inverted image (all LSBs inverted)
    blocks_inv = blocks ^ 1
    f0_i = f_disc(blocks_inv)
    f_pos_i = f_disc(f_flip(blocks_inv, 1))
    f_neg_i = f_disc(f_flip(blocks_inv, -1))

    r_m1 = float(np.mean(f_pos_i > f0_i))
    s_m1 = float(np.mean(f_pos_i < f0_i))
    r_nm1 = float(np.mean(f_neg_i > f0_i))
    s_nm1 = float(np.mean(f_neg_i < f0_i))

    d0 = r_m - s_m
    dn0 = r_nm - s_nm
    d1 = r_m1 - s_m1
    dn1 = r_nm1 - s_nm1

    # Solve quadratic equation for intersection point
    # a * z^2 + b * z + c = 0
    a = 2.0 * (d1 + d0)
    b = dn0 - dn1 - d1 - 3.0 * d0
    c = d0 - dn0

    p = 0.0
    disc = b * b - 4.0 * a * c
    if abs(a) > 1e-6 and disc >= 0:
        z1 = (-b + np.sqrt(disc)) / (2.0 * a)
        z2 = (-b - np.sqrt(disc)) / (2.0 * a)
        z = z1 if abs(z1) < abs(z2) else z2
        if abs(z - 0.5) > 1e-5:
            p = z / (z - 0.5)
    elif abs(b) > 1e-6:
        z = -c / b
        if abs(z - 0.5) > 1e-5:
            p = z / (z - 0.5)

    p = max(0.0, min(1.0, float(abs(p))))

    return p, {
        "r_m": round(r_m, 4),
        "s_m": round(s_m, 4),
        "r_nm": round(r_nm, 4),
        "s_nm": round(s_nm, 4),
        "rs_divergence": round(abs(d0 - dn0), 4),
    }


def _spa_analyze_channel(channel_1d: np.ndarray) -> float:
    """Sample Pair Analysis (Dumitrescu et al.) on 1D horizontal pixel sequences.

    Returns:
      estimated_rate (float between 0.0 and 1.0)
    """
    pixels = np.array(channel_1d, dtype=np.int32)
    if len(pixels) < 20:
        return 0.0

    u = pixels[:-1]
    v = pixels[1:]
    u_h, v_h = u >> 1, v >> 1
    u_lsb, v_lsb = u & 1, v & 1

    x_count = np.sum((u_h == v_h) & (u != v))
    d = u_h - v_h
    y_count = np.sum((d == 1) & (u_lsb == 0) & (v_lsb == 1)) + np.sum((d == -1) & (u_lsb == 1) & (v_lsb == 0))
    z_count = np.sum((d == 1) & (u_lsb == 1) & (v_lsb == 0)) + np.sum((d == -1) & (u_lsb == 0) & (v_lsb == 1))
    w_count = np.sum((np.abs(d) == 1) & (u_lsb == v_lsb))

    a = 0.5 * (w_count + z_count - y_count - x_count)
    b = 2.0 * x_count - w_count
    c = float(y_count - z_count)

    if abs(a) < 1e-6:
        if abs(b) > 1e-6:
            r = -c / b
            if 0.0 <= r <= 0.5:
                return float(min(1.0, 2.0 * r))
        return 0.0

    disc = b * b - 4.0 * a * c
    if disc < 0:
        return 0.0

    r1 = (-b + np.sqrt(disc)) / (2.0 * a)
    r2 = (-b - np.sqrt(disc)) / (2.0 * a)
    valid = [r for r in [r1, r2] if 0.0 <= r <= 0.5]
    if valid:
        return float(min(1.0, 2.0 * valid[0]))
    return 0.0


def analyze_rs(image_path: str) -> dict:
    """Perform RS Steganalysis and Sample Pair Analysis (SPA) across all color channels.

    Estimates the percentage of pixels modified by LSB steganography without
    requiring any magic header or length prefix.

    Returns a dict with:
      - ``suspicious``: bool
      - ``reasons``: list of findings
      - ``rs_rates``: dict of per-channel RS rates (0.0 to 1.0)
      - ``spa_rates``: dict of per-channel SPA rates (0.0 to 1.0)
      - ``mean_rs_rate``: average RS embedding rate across channels
      - ``estimated_message_bytes``: estimated total payload capacity in bytes
    """
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    arr = np.array(img, dtype=np.uint8)

    channels = {"R": arr[:, :, 0], "G": arr[:, :, 1], "B": arr[:, :, 2]}

    rs_rates: dict[str, float] = {}
    spa_rates: dict[str, float] = {}
    details: dict[str, dict] = {}
    reasons: list[str] = []
    suspicious = False

    total_pixels = w * h

    for ch_name, ch_arr in channels.items():
        rate_rs, rs_det = _rs_analyze_channel(ch_arr)
        rate_spa = _spa_analyze_channel(ch_arr.flatten())

        rs_rates[ch_name] = round(rate_rs, 4)
        spa_rates[ch_name] = round(rate_spa, 4)
        details[ch_name] = rs_det

        # Flag if RS rate is statistically significant (> 5% embedding rate)
        if rate_rs > 0.08:
            suspicious = True
            reasons.append(
                f"RS Analysis: ~{rate_rs * 100:.1f}% estimated LSB modification in {ch_name} channel "
                f"(divergence={rs_det.get('rs_divergence', 0)})"
            )
        elif rs_det.get("rs_divergence", 0) > 0.05:
            suspicious = True
            reasons.append(
                f"RS Curve Discrepancy: anomalous R/S curve asymmetry ({rs_det['rs_divergence']:.4f}) in {ch_name} channel"
            )

    mean_rs = float(np.mean(list(rs_rates.values())))
    mean_spa = float(np.mean(list(spa_rates.values())))

    # Estimated payload length: mean embedding rate * 3 channels * total_pixels / 8 bits
    estimated_bytes = int(round((mean_rs * total_pixels * 3) / 8))

    return {
        "suspicious": suspicious,
        "reasons": reasons,
        "rs_rates": rs_rates,
        "spa_rates": spa_rates,
        "mean_rs_rate": round(mean_rs, 4),
        "mean_spa_rate": round(mean_spa, 4),
        "estimated_message_bytes": estimated_bytes if suspicious else 0,
        "details": details,
    }
