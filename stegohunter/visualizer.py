"""Visual steganography analysis — bit-plane slicing, composite grids, and spatial anomaly heatmaps."""

from __future__ import annotations

import math
from typing import Optional

import numpy as np
from PIL import Image, ImageDraw

from .analyzers.common import entropy


def colormap_heatmap(v: np.ndarray) -> np.ndarray:
    """Map normalized values [0, 1] to RGB heatmap array (H, W, 3) uint8.

    Gradient:
      0.00: Deep Blue  [0, 0, 255]
      0.25: Cyan       [0, 255, 255]
      0.50: Green      [0, 255, 0]
      0.75: Yellow     [255, 255, 0]
      1.00: Red        [255, 0, 0]
    """
    v = np.clip(v, 0.0, 1.0)
    r = np.zeros_like(v, dtype=np.float64)
    g = np.zeros_like(v, dtype=np.float64)
    b = np.zeros_like(v, dtype=np.float64)

    # [0.0, 0.25]: Blue -> Cyan
    m1 = v < 0.25
    t1 = v[m1] / 0.25
    b[m1] = 1.0
    g[m1] = t1

    # [0.25, 0.5]: Cyan -> Green
    m2 = (v >= 0.25) & (v < 0.5)
    t2 = (v[m2] - 0.25) / 0.25
    g[m2] = 1.0
    b[m2] = 1.0 - t2

    # [0.5, 0.75]: Green -> Yellow
    m3 = (v >= 0.5) & (v < 0.75)
    t3 = (v[m3] - 0.5) / 0.25
    g[m3] = 1.0
    r[m3] = t3

    # [0.75, 1.0]: Yellow -> Red
    m4 = v >= 0.75
    t4 = (v[m4] - 0.75) / 0.25
    r[m4] = 1.0
    g[m4] = 1.0 - t4

    rgb = np.stack([r, g, b], axis=-1) * 255.0
    return rgb.astype(np.uint8)


def extract_bit_plane(image_path: str, channel: str = "R", bit: int = 0) -> Image.Image:
    """Extract a single bit-plane (0=LSB to 7=MSB) from a chosen channel.

    Returns a high-contrast 8-bit grayscale PIL Image (0 or 255).
    """
    if not (0 <= bit <= 7):
        raise ValueError("bit must be between 0 (LSB) and 7 (MSB)")

    img = Image.open(image_path)
    ch = channel.upper()

    if ch == "GRAY" or img.mode in ("L", "1"):
        img = img.convert("L")
        arr = np.array(img, dtype=np.uint8)
    else:
        img = img.convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        ch_idx = {"R": 0, "G": 1, "B": 2}.get(ch, 0)
        arr = arr[:, :, ch_idx]

    # Extract target bit and scale to 0 / 255
    bit_plane = ((arr >> bit) & 1) * 255
    return Image.fromarray(bit_plane.astype(np.uint8), mode="L")


def generate_bitplane_grid(image_path: str, channel: str = "R") -> Image.Image:
    """Generate a 2x4 composite comparison grid showing bit 0 (LSB) through bit 7 (MSB)."""
    img = Image.open(image_path)
    orig_w, orig_h = img.size

    # Scale thumbnails down if source image is excessively large
    max_thumb_w, max_thumb_h = 320, 240
    scale = min(max_thumb_w / orig_w, max_thumb_h / orig_h, 1.0)
    thumb_w = max(64, int(orig_w * scale))
    thumb_h = max(64, int(orig_h * scale))

    header_h = 24
    cell_w = thumb_w + 10
    cell_h = thumb_h + header_h + 10

    grid_w = cell_w * 4 + 10
    grid_h = cell_h * 2 + 10

    grid_img = Image.new("RGB", (grid_w, grid_h), color=(20, 20, 24))
    draw = ImageDraw.Draw(grid_img)

    for bit in range(8):
        row = bit // 4
        col = bit % 4

        x_offset = 10 + col * cell_w
        y_offset = 10 + row * cell_h

        plane = extract_bit_plane(image_path, channel=channel, bit=bit)
        if (plane.width, plane.height) != (thumb_w, thumb_h):
            plane = plane.resize((thumb_w, thumb_h), Image.Resampling.NEAREST)

        # Convert plane to RGB to paste into grid
        plane_rgb = plane.convert("RGB")
        grid_img.paste(plane_rgb, (x_offset, y_offset + header_h))

        label = f"Bit {bit} ({'LSB' if bit == 0 else 'MSB' if bit == 7 else 'Data'})"
        draw.text((x_offset + 2, y_offset + 4), label, fill=(220, 220, 220))
        # Draw cell border
        draw.rectangle(
            [x_offset - 1, y_offset + header_h - 1, x_offset + thumb_w, y_offset + header_h + thumb_h],
            outline=(60, 60, 70),
        )

    return grid_img


def generate_spatial_heatmap(
    image_path: str,
    block_size: int = 16,
    channel: str = "all",
    alpha: float = 0.5,
) -> tuple[Image.Image, dict]:
    """Generate a spatial anomaly heatmap highlighting localized steganographic clusters.

    Parameters:
      image_path: path to the target image
      block_size: size in pixels of the sliding block window (e.g. 8, 16, 32)
      channel: 'R', 'G', 'B', or 'all'
      alpha: overlay opacity (0.0 = pure heatmap, 1.0 = original image, 0.5 = 50% blend)

    Returns:
      (visual_image, metrics_dict)
    """
    orig_img = Image.open(image_path).convert("RGB")
    w, h = orig_img.size
    arr = np.array(orig_img, dtype=np.uint8)

    ch = channel.upper()
    if ch in ("R", "G", "B"):
        ch_idx = {"R": 0, "G": 1, "B": 2}[ch]
        data = arr[:, :, ch_idx : ch_idx + 1]
    else:
        data = arr  # all channels

    n_blocks_y = max(1, math.ceil(h / block_size))
    n_blocks_x = max(1, math.ceil(w / block_size))
    score_grid = np.zeros((n_blocks_y, n_blocks_x), dtype=np.float64)

    max_score = 0.0
    hottest_block = (0, 0)

    for by in range(n_blocks_y):
        y0 = by * block_size
        y1 = min(h, y0 + block_size)
        for bx in range(n_blocks_x):
            x0 = bx * block_size
            x1 = min(w, x0 + block_size)

            block = data[y0:y1, x0:x1]
            # Extract LSB bits
            lsb_bits = (block & 1).flatten()
            if len(lsb_bits) < 4:
                continue

            ent = entropy(bytes(lsb_bits.tolist()))
            r1 = float(np.sum(lsb_bits)) / len(lsb_bits)
            dev = abs(r1 - 0.5)

            # Anomaly scoring:
            # High entropy (>0.9) and balanced 1-ratio (dev near 0) indicate random/stego content
            ent_norm = np.clip((ent - 0.3) / 0.7, 0.0, 1.0)
            balance = np.clip(1.0 - 2.5 * dev, 0.0, 1.0)
            score = float(ent_norm * balance)

            score_grid[by, bx] = score
            if score > max_score:
                max_score = score
                hottest_block = (bx, by)

    # Upscale score grid to original image dimensions
    heatmap_small = colormap_heatmap(score_grid)
    heatmap_img = Image.fromarray(heatmap_small, mode="RGB").resize((w, h), Image.Resampling.BILINEAR)

    # Blend with original if alpha > 0
    alpha = max(0.0, min(1.0, alpha))
    if alpha <= 0.01:
        out_img = heatmap_img
    elif alpha >= 0.99:
        out_img = orig_img
    else:
        out_img = Image.blend(heatmap_img, orig_img, alpha)

    mean_anomaly = float(np.mean(score_grid))
    suspicious_count = int(np.sum(score_grid > 0.85))
    total_blocks = n_blocks_x * n_blocks_y

    hx, hy = hottest_block
    hottest_region = {
        "x": hx * block_size,
        "y": hy * block_size,
        "width": min(block_size, w - hx * block_size),
        "height": min(block_size, h - hy * block_size),
        "score": round(max_score, 4),
    }

    metrics = {
        "image_size": (w, h),
        "block_size": block_size,
        "total_blocks": total_blocks,
        "mean_anomaly_score": round(mean_anomaly, 4),
        "max_anomaly_score": round(max_score, 4),
        "suspicious_blocks_count": suspicious_count,
        "suspicious_blocks_pct": round(suspicious_count / max(1, total_blocks) * 100.0, 2),
        "hottest_region": hottest_region,
    }

    return out_img, metrics
