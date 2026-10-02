"""LSB extraction — pull hidden data out of LSB bit-planes."""

from __future__ import annotations

from typing import Optional


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a list of 0/1 bits into bytes."""
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


def extract_lsb_message(
    image_path: str,
    mode: str = "auto",
    bit: int = 0,
    channel: Optional[str] = None,
    max_bytes: int = 8192,
) -> dict:
    """Extract a hidden message from LSB bit-planes.

    ``mode`` can be:
      - ``"auto"``: use all RGB channels sequentially, stop when a NULL
        terminator or low-entropy stretch is reached
      - ``"row"``: LSBs of every pixel, MSB-first per pixel
      - ``"single"``: LSB of a single specified channel (R/G/B), MSB-first

    Returns a dict with:
      - ``extracted``: bytes — the raw extracted message
      - ``length``: int
      - ``mode_used``: str
      - ``null_terminated``: bool
    """
    from PIL import Image

    img = Image.open(image_path).convert("RGB")
    pixels = list(img.get_flattened_data())

    if mode == "single":
        if channel is None:
            raise ValueError("mode='single' requires a channel")
        ch_map = {"R": 0, "G": 1, "B": 2}
        idx = ch_map[channel.upper()]
        vals = [p[idx] for p in pixels]
        bits = [(v >> bit) & 1 for v in vals]
        raw = _bits_to_bytes(bits)
        return {
            "extracted": raw[:max_bytes],
            "length": min(len(raw), max_bytes),
            "mode_used": f"single:{channel}{bit}",
            "null_terminated": False,
        }

    elif mode == "row":
        # Sequential RGB: R0,G0,B0,R1,G1,B1,...
        flat = [v for p in pixels for v in p]
        bits = [v & 1 for v in flat]
        raw = _bits_to_bytes(bits)
        return {
            "extracted": raw[:max_bytes],
            "length": min(len(raw), max_bytes),
            "mode_used": "row",
            "null_terminated": False,
        }

    else:  # auto
        flat = [v for p in pixels for v in p]
        bits = [v & 1 for v in flat]
        raw = bytearray(_bits_to_bytes(bits))

        # Try to find a NULL terminator (common convention: message ends with \x00)
        # Or a 4-byte length prefix (big-endian)
        null_pos = raw.find(b"\x00")
        extracted: bytes
        length: int
        null_term = False

        if len(raw) >= 4:
            length_prefix = int.from_bytes(raw[:4], "big")
            if 0 < length_prefix < 1_000_000:
                # Prefixed message
                extracted = bytes(raw[4:4 + length_prefix])
                length = length_prefix
            elif null_pos != -1:
                extracted = bytes(raw[:null_pos])
                length = null_pos
                null_term = True
            else:
                extracted = bytes(raw)
                length = len(raw)
        elif null_pos != -1:
            extracted = bytes(raw[:null_pos])
            length = null_pos
            null_term = True
        else:
            extracted = bytes(raw)
            length = len(raw)

        return {
            "extracted": extracted[:max_bytes],
            "length": min(length, max_bytes),
            "mode_used": "auto",
            "null_terminated": null_term,
        }