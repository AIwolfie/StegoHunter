"""Audio steganalysis — WAV LSB analysis and extraction."""

from __future__ import annotations

import struct
from typing import Optional

from ..analyzers.common import entropy


def _read_wav(path: str) -> tuple[bytes, dict]:
    """Read WAV file, return (audio_data_bytes, info_dict)."""
    with open(path, "rb") as f:
        data = f.read()

    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("Not a RIFF/WAVE file")

    # Parse fmt and data chunks
    fmt_info = {
        "num_channels": 1,
        "sample_rate": 44100,
        "bits_per_sample": 16,
    }
    audio_start = None
    audio_end = None
    pos = 12
    while pos + 8 <= len(data):
        chunk_id = data[pos:pos + 4]
        chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
        if chunk_id == b"fmt ":
            if chunk_size >= 16:
                fmt_info["num_channels"] = struct.unpack_from("<H", data, pos + 10)[0]
                fmt_info["sample_rate"] = struct.unpack_from("<I", data, pos + 12)[0]
                fmt_info["bits_per_sample"] = struct.unpack_from("<H", data, pos + 22)[0]
        elif chunk_id == b"data":
            audio_start = pos + 8
            audio_end = pos + 8 + chunk_size
        pos = pos + 8 + chunk_size + (chunk_size % 2)  # chunks are 2-byte aligned

    if audio_start is None or audio_end is None:
        raise ValueError("No data chunk found")

    audio_data = data[audio_start:audio_end]
    fmt_info["audio_offset"] = audio_start
    fmt_info["audio_end"] = audio_end
    fmt_info["file_size"] = len(data)
    return audio_data, fmt_info


def analyze_lsb_wav(path: str) -> dict:
    """Analyze LSB plane of a WAV file.

    Returns:
      - ``suspicious``: bool
      - ``bits_per_sample``: int
      - ``num_channels``: int
      - ``sample_rate``: int
      - ``lsb_entropy``: float — entropy of LSB bit stream
      - ``lsb_ratio``: float — proportion of 1-bits
      - ``msb_entropy``: float — entropy of the most significant bit (control)
      - ``chi_square_p``: float
      - ``sample_count``: int
      - ``recomputed_message_length``: int|None
      - ``note``: str
    """
    audio_data, fmt = _read_wav(path)
    bps = fmt["bits_per_sample"]
    if bps not in (8, 16, 24, 32):
        return {
            **fmt,
            "suspicious": False,
            "lsb_entropy": 0.0,
            "lsb_ratio": 0.0,
            "msb_entropy": 0.0,
            "chi_square_p": 1.0,
            "sample_count": 0,
            "recomputed_message_length": None,
            "note": f"Unsupported bits-per-sample: {bps}",
        }

    nbytes = bps // 8
    samples: list[int] = []
    for i in range(0, len(audio_data) - nbytes + 1, nbytes):
        raw = audio_data[i:i + nbytes]
        # Interpret as signed little-endian
        samples.append(int.from_bytes(raw, "little", signed=True))

    if not samples:
        return {**fmt, "suspicious": False, "note": "No samples", "sample_count": 0}

    # LSB bits
    lsb_bits = [abs(s) & 1 for s in samples]
    lsb_entropy = entropy(bytes(lsb_bits))
    lsb_ratio = sum(lsb_bits) / len(lsb_bits)

    # MSB control bits — should be very structured
    msb_bits = [(abs(s) >> (bps - 1)) & 1 for s in samples]
    msb_entropy = entropy(bytes(msb_bits))

    # Chi-square on 2-bit pairs of LSBs
    pairs = [lsb_bits[i] * 2 + lsb_bits[i + 1] for i in range(0, len(lsb_bits) - 1, 2)]
    hist = [0] * 4
    for v in pairs:
        hist[v] += 1
    from ..analyzers.lsb import _chi_square_uniform
    _, p = _chi_square_uniform(hist)

    # Heuristic: LSB entropy close to 1.0 (random) with balanced ratio is what
    # *clean* audio looks like; suspicious when LSB is too structured OR
    # too different from MSB structure.
    suspicious = False
    note = ""
    if lsb_entropy < 0.85:
        suspicious = True
        note = "Low LSB entropy — bit stream is more structured than expected"
    if p < 0.01:
        suspicious = True
        note = (note + "; " if note else "") + "Chi-square test rejects uniform LSB distribution"

    # Reconstruct message bytes
    raw_bytes = bytearray()
    bits = lsb_bits[:]
    while len(bits) % 8:
        bits.append(0)
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        raw_bytes.append(byte)

    msg_len = None
    if len(raw_bytes) >= 4:
        candidate = int.from_bytes(raw_bytes[:4], "big")
        if 0 < candidate < len(raw_bytes) - 4:
            msg_len = candidate

    return {
        **fmt,
        "suspicious": suspicious,
        "lsb_entropy": round(lsb_entropy, 4),
        "lsb_ratio": round(lsb_ratio, 4),
        "msb_entropy": round(msb_entropy, 4),
        "chi_square_p": round(p, 6),
        "sample_count": len(samples),
        "recomputed_message_length": msg_len,
        "note": note,
    }


def extract_lsb_wav(path: str, max_bytes: int = 65536) -> dict:
    """Extract LSB message from WAV file."""
    audio_data, fmt = _read_wav(path)
    bps = fmt["bits_per_sample"]
    nbytes = bps // 8
    samples: list[int] = []
    for i in range(0, len(audio_data) - nbytes + 1, nbytes):
        raw = audio_data[i:i + nbytes]
        samples.append(int.from_bytes(raw, "little", signed=True))

    bits = [abs(s) & 1 for s in samples]
    while len(bits) % 8:
        bits.append(0)
    raw = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        raw.append(byte)
    raw = bytes(raw)

    # Find length prefix or NULL terminator
    extracted: bytes
    length: int
    null_term = False
    if len(raw) >= 4:
        prefix = int.from_bytes(raw[:4], "big")
        if 0 < prefix < min(len(raw) - 4, 10_000_000):
            extracted = raw[4:4 + prefix]
            length = prefix
        else:
            null_pos = raw.find(b"\x00")
            if null_pos != -1:
                extracted = raw[:null_pos]
                length = null_pos
                null_term = True
            else:
                extracted = raw
                length = len(raw)
    else:
        extracted = raw
        length = len(raw)

    return {
        "extracted": extracted[:max_bytes],
        "length": min(length, max_bytes),
        "null_terminated": null_term,
        "bits_per_sample": bps,
        "channels": fmt["num_channels"],
    }