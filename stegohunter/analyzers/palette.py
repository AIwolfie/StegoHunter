"""Palette-based steganalysis — detect duplicate colors, unusual palette sizes, and
color-frequency anomalies in indexed (palette) images."""

from __future__ import annotations

from collections import Counter


def analyze_palette(image_path: str) -> dict:
    """Analyze a palette-based image for steganographic manipulation.

    Returns a dict with:
      - ``has_palette``: bool
      - ``palette_size``: int
      - ``max_palette_size``: int (mode-dependent)
      - ``used_colors``: int
      - ``duplicate_colors``: int
      - ``color_frequency_entropy``: float
      - ``suspicious``: bool
      - ``details``: list of findings
    """
    from PIL import Image

    img = Image.open(image_path)

    details: list[str] = []

    # --- Check if palette-based ---
    if img.mode not in ("P", "PA"):
        return {
            "has_palette": False,
            "palette_size": 0,
            "max_palette_size": 0,
            "used_colors": 0,
            "duplicate_colors": 0,
            "color_frequency_entropy": 0.0,
            "suspicious": False,
            "details": ["Image is not palette-based (mode={})".format(img.mode)],
        }

    palette_obj = img.getpalette()
    if not palette_obj:
        return {
            "has_palette": True,
            "palette_size": 0,
            "max_palette_size": 0,
            "used_colors": 0,
            "duplicate_colors": 0,
            "color_frequency_entropy": 0.0,
            "suspicious": False,
            "details": ["Image has no palette data despite P mode"],
        }

    # Newer Pillow returns a PaletteImage object; normalize to a flat list
    if hasattr(palette_obj, "getdata"):
        palette = list(palette_obj.getdata())
    elif hasattr(palette_obj, "tobytes"):
        palette = list(palette_obj.tobytes())
    else:
        palette = list(palette_obj)

    # Palette is stored as [R,G,B,R,G,B,...] — 256 entries max
    # Each entry is 3 bytes (R,G,B)
    raw_entries = len(palette) // 3
    max_entries = 256 if img.mode == "P" else 256

    # Build list of (R,G,B) tuples
    colors: list[tuple[int, int, int]] = [
        (palette[i * 3], palette[i * 3 + 1], palette[i * 3 + 2])
        for i in range(raw_entries)
    ]
    # Trim trailing all-zero entries (standard palette padding). Kept for the
    # "unused" analysis, but excluded from duplicate detection since every
    # zero-padded entry is identical by definition.
    palette_size = len(colors)
    while colors and colors[-1] == (0, 0, 0):
        colors.pop()
    defined_size = len(colors)
    palette_size = defined_size

    # --- Duplicate colors (only within the defined palette region) ---
    seen: set[tuple[int, int, int]] = set()
    dupes: list[tuple[int, int, int]] = []
    for c in colors:
        if c in seen:
            dupes.append(c)
        else:
            seen.add(c)
    duplicate_count = len(dupes)

    # --- Actual pixel usage ---
    pixels = list(img.get_flattened_data())
    pixel_counter = Counter(pixels)  # pixel value -> count
    used_colors = len(pixel_counter)
    max_color_val = max(pixel_counter.keys()) if pixel_counter else 0

    # --- Color frequency entropy ---
    from .common import entropy
    freq_bytes = bytes(
        v for idx in range(palette_size) for v in (pixel_counter.get(idx, 0),)
    )
    freq_entropy = entropy(freq_bytes)

    # --- Suspicion heuristics ---
    # 1. Duplicate colors in palette → possible data stored in unused entries
    if duplicate_count > 0:
        details.append(
            f"Found {duplicate_count} duplicate color entries in palette"
        )

    # 2. Many unused palette entries — but only suspicious if the *trailing* entries
    #    (which are normally zero-padding) have non-zero values, or if the gap between
    #    used_colors and palette_size is large relative to palette_size.
    unused = palette_size - used_colors
    unused_ratio = unused / palette_size if palette_size else 0
    if unused_ratio > 0.5 and unused > 20:
        details.append(f"{unused}/{palette_size} palette entries unused ({unused_ratio:.0%})")

    # 3. Unused entries that are non-zero — but only flag if they're in the *middle*,
    #    not the trailing padding (which is often zero-padded).
    #    Find the highest used index; anything beyond that is padding.
    if pixel_counter:
        max_used_idx = max(pixel_counter.keys())
    else:
        max_used_idx = 0
    non_zero_padding = [c for idx, c in enumerate(colors) if idx > max_used_idx and c != (0, 0, 0)]
    # Also check for unused entries *before* max_used_idx (gaps in the palette)
    unused_gaps = [idx for idx in range(max_used_idx + 1) if idx not in pixel_counter]
    flag_gaps = False
    if len(unused_gaps) > max_used_idx * 0.3 and max_used_idx > 10:
        flag_gaps = True
        details.append(f"{len(unused_gaps)} palette gaps before index {max_used_idx}")

    # 4. Low frequency entropy → same colors used way too often or too little
    if freq_entropy < 0.5 and used_colors > 1:
        details.append(
            f"Low color frequency entropy ({freq_entropy:.3f}) — skewed distribution"
        )

    suspicious = bool(
        duplicate_count > 0
        or flag_gaps
        or non_zero_padding
        or (freq_entropy < 0.5 and used_colors > 1)
    )

    return {
        "has_palette": True,
        "palette_size": palette_size,
        "max_palette_size": max_entries,
        "used_colors": used_colors,
        "duplicate_colors": duplicate_count,
        "color_frequency_entropy": round(freq_entropy, 4),
        "suspicious": suspicious,
        "details": details,
    }