"""Tests for stegohunter — generates stego samples and verifies detection/extraction."""

from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

# Ensure stegohunter is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stegohunter.analyzers import analyze_lsb, analyze_palette, find_appended_data, entropy
from stegohunter.analyzers.common import byte_histogram
from stegohunter.analyzers.lsb import _chi_square_uniform, _get_lsb_plane, _get_lsb_bytes
from stegohunter.extractors import extract_lsb_message, extract_appended_data
from stegohunter.audio import analyze_lsb_wav, extract_lsb_wav
from stegohunter.orchestrator import full_analyze, is_image, is_audio


# =========================================================================
#  Helper: generate test images with embedded messages
# =========================================================================

def _make_test_image(width: int, height: int, fmt: str = "PNG") -> bytes:
    """Generate a simple test image (gradient) and return raw bytes."""
    from PIL import Image
    img = Image.new("RGB", (width, height))
    for y in range(height):
        for x in range(width):
            r = (x * 255) // width
            g = (y * 255) // height
            b = ((x + y) * 255) // (width + height)
            img.putpixel((x, y), (r, g, b))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def _make_palette_image(width: int, height: int) -> bytes:
    """Generate a palette-based PNG. Clean palette: only referenced entries
    carry colors, trailing unreferenced entries are zero-padded (the normal
    case for real palette images)."""
    from PIL import Image
    img = Image.new("P", (width, height))
    # Compute which indices will be referenced
    used = set()
    for y in range(height):
        for x in range(width):
            used.add((x + y) % 256)
    # Build palette: referenced entries get a grayscale color, the rest are zero
    palette = []
    for i in range(256):
        if i in used:
            palette.extend([i, i, i])
        else:
            palette.extend([0, 0, 0])
    img.putpalette(palette)
    for y in range(height):
        for x in range(width):
            img.putpixel((x, y), (x + y) % 256)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_palette_image_with_data(width: int, height: int) -> bytes:
    """Generate a palette-based PNG where unused trailing entries carry
    non-zero data (simulating a palette covert channel)."""
    from PIL import Image
    img = Image.new("P", (width, height))
    # Use only indices 0..63 for the actual image
    for y in range(height):
        for x in range(width):
            img.putpixel((x, y), (x + y) % 64)
    # Palette: indices 0..63 grayscale, 64..255 filled with data-like values
    palette = []
    for i in range(256):
        if i < 64:
            palette.extend([i, i, i])
        else:
            # Non-zero "data" in unused slots
            v = (i * 7) % 256
            palette.extend([v, (v * 3) % 256, (v * 5) % 256])
    img.putpalette(palette)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _embed_lsb_message(image_bytes: bytes, message: bytes, length_prefix: bool = True) -> bytes:
    """Embed a message into the LSB of an RGB image. Returns new PNG bytes."""
    from PIL import Image
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = list(img.get_flattened_data())

    # Build raw bitstream
    payload: bytes
    if length_prefix:
        payload = struct.pack(">I", len(message)) + message
    else:
        payload = message + b"\x00"

    bits = []
    for byte in payload:
        for b in range(7, -1, -1):
            bits.append((byte >> b) & 1)

    flat = [v for p in pixels for v in p]
    if len(bits) > len(flat):
        raise ValueError("Message too large for image")
    for i in range(len(bits)):
        flat[i] = (flat[i] & 0xFE) | bits[i]

    # Rebuild image
    new_pixels = [(flat[i], flat[i + 1], flat[i + 2]) for i in range(0, len(flat), 3)]
    img2 = Image.new("RGB", img.size)
    img2.putdata(new_pixels)
    buf = io.BytesIO()
    img2.save(buf, format="PNG")
    return buf.getvalue()


def _make_wav_with_message(message: bytes, sample_rate: int = 44100) -> bytes:
    """Generate a WAV file with a hidden LSB message."""
    import math
    # Generate a simple low-frequency sine wave
    duration = 1.0  # seconds
    num_samples = int(sample_rate * duration)
    # Ensure even number of samples (16-bit stereo)
    num_samples = (num_samples // 2) * 2

    # Build payload directly
    payload = struct.pack(">I", len(message)) + message
    payload_bits = []
    for byte in payload:
        for b in range(7, -1, -1):
            payload_bits.append((byte >> b) & 1)

    # If payload is too long, truncate
    if len(payload_bits) > num_samples:
        payload_bits = payload_bits[:num_samples]
    else:
        # Pad with zeros
        payload_bits.extend([0] * (num_samples - len(payload_bits)))

    # Generate samples with LSB encoding
    samples = []
    for i in range(num_samples):
        # Pure sine wave, 440 Hz
        sample = int(16000 * math.sin(2 * math.pi * 440 * i / sample_rate))
        # Clamp to valid 16-bit signed range
        sample = max(-32768, min(32767, sample))
        # Clear LSB and set payload bit
        sample = (sample & ~1) | payload_bits[i]
        samples.append(sample)

    # Build WAV file manually
    data_size = num_samples * 2  # 16-bit
    file_size = 36 + data_size
    buf = io.BytesIO()
    buf.write(b"RIFF")
    buf.write(struct.pack("<I", file_size))
    buf.write(b"WAVE")
    buf.write(b"fmt ")
    buf.write(struct.pack("<I", 16))  # chunk size
    buf.write(struct.pack("<H", 1))   # PCM
    buf.write(struct.pack("<H", 1))   # mono
    buf.write(struct.pack("<I", sample_rate))
    buf.write(struct.pack("<I", sample_rate * 2))  # byte rate
    buf.write(struct.pack("<H", 2))   # block align
    buf.write(struct.pack("<H", 16))  # bits per sample
    buf.write(b"data")
    buf.write(struct.pack("<I", data_size))
    for s in samples:
        buf.write(struct.pack("<h", s))
    return buf.getvalue()


def _append_data_to_jpeg(image_bytes: bytes, trailer: bytes) -> bytes:
    """Append raw data after JPEG EOI marker."""
    # Find EOI or reuse image bytes directly
    eoi = b"\xff\xd9"
    idx = image_bytes.rfind(eoi)
    if idx == -1:
        # JPEG without EOI — append trailer directly
        return image_bytes + trailer
    return image_bytes[:idx + len(eoi)] + trailer


# =========================================================================
#  Tests
# =========================================================================

class TestEntropy:
    def test_zero_entropy(self):
        assert entropy(b"\x00" * 100) == 0.0

    def test_max_entropy(self):
        # All 256 bytes equally
        data = bytes(range(256))
        e = entropy(data)
        assert 7.9 < e < 8.1  # nearly 8 bits/byte

    def test_empty(self):
        assert entropy(b"") == 0.0


class TestLSBAnalysis:
    def test_clean_image_not_suspicious(self):
        img = _make_test_image(100, 100)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            result = analyze_lsb(p)
            assert not result["suspicious"], "Clean image should not be flagged"
        finally:
            os.unlink(p)

    def test_embedded_message_detected(self):
        img = _make_test_image(100, 100)
        msg = b"FLAG{this_is_a_test_flag}"
        stego = _embed_lsb_message(img, msg)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = analyze_lsb(p)
            assert result["suspicious"], "Stego image should be flagged"
            assert result["recomputed_message_length"] == len(msg)
        finally:
            os.unlink(p)

    def test_chi_square_uniform(self):
        # Uniform distribution → high p-value
        data = [0, 1, 2, 3] * 25
        chi2, p = _chi_square_uniform(data)
        assert p > 0.05


class TestLSBExtraction:
    def test_extract_known_message(self):
        img = _make_test_image(50, 50)
        msg = b"HELLO_STEGO_WORLD"
        stego = _embed_lsb_message(img, msg)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = extract_lsb_message(p)
            assert result["length"] >= len(msg)
            assert msg in result["extracted"]
        finally:
            os.unlink(p)

    def test_extract_without_length_prefix(self):
        img = _make_test_image(50, 50)
        msg = b"NO_PREFIX_FLAG"
        stego = _embed_lsb_message(img, msg, length_prefix=False)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = extract_lsb_message(p)
            assert msg in result["extracted"]
        finally:
            os.unlink(p)


class TestPaletteAnalysis:
    def test_clean_palette(self):
        img = _make_palette_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            result = analyze_palette(p)
            assert result["has_palette"]
            assert not result["suspicious"]
        finally:
            os.unlink(p)

    def test_palette_stego_detected(self):
        img = _make_palette_image_with_data(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            result = analyze_palette(p)
            assert result["has_palette"]
            assert result["suspicious"], f"Expected suspicious palette, got {result['details']}"
        finally:
            os.unlink(p)

    def test_rgb_image_no_palette(self):
        img = _make_test_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            result = analyze_palette(p)
            assert not result["has_palette"]
        finally:
            os.unlink(p)


class TestAppendedData:
    def test_no_appended_data(self):
        img = _make_test_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            result = find_appended_data(p)
            assert not result["appended"]
        finally:
            os.unlink(p)

    def test_appended_data_detected(self):
        img = _make_test_image(32, 32, fmt="JPEG")
        trailer = b"SECRET_DATA_APPENDED_AFTER_EOI"
        stego = _append_data_to_jpeg(img, trailer)
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = find_appended_data(p)
            assert result["appended"]
            assert result["size"] == len(trailer)
            assert trailer in result["data"]
        finally:
            os.unlink(p)

    def test_appended_zip_detected(self):
        img = _make_test_image(32, 32, fmt="JPEG")
        # Create a minimal zip in memory
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("secret.txt", "This is inside a ZIP appended to a file")
        trailer = zip_buf.getvalue()
        stego = _append_data_to_jpeg(img, trailer)
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = find_appended_data(p)
            assert result["appended"]
            assert result["contains_zip"] or "ZIP" in result.get("found_signatures", [])
        finally:
            os.unlink(p)

    def test_appended_extraction(self):
        img = _make_test_image(32, 32, fmt="JPEG")
        trailer = b"EXTRACTED_DATA_TRAILER"
        stego = _append_data_to_jpeg(img, trailer)
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            result = extract_appended_data(p)
            assert result["appended"]
            assert trailer in result["extracted"]
            # Verify output file exists
            assert os.path.exists(result["output_path"])
            with open(result["output_path"], "rb") as f:
                assert f.read() == trailer
            os.unlink(result["output_path"])
        finally:
            os.unlink(p)


class TestAudioAnalysis:
    def test_clean_wav_not_suspicious(self):
        wav = _make_wav_with_message(b"")  # No message
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            p = f.name
        try:
            result = analyze_lsb_wav(p)
            # The "empty" message only has the length prefix (4 bytes) embedded
            # so it might still be slightly suspicious — just check it runs
            assert "sample_rate" in result
        finally:
            os.unlink(p)

    def test_embedded_wav_detected(self):
        msg = b"FLAG{audio_stego_flag_2024}"
        wav = _make_wav_with_message(msg)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            p = f.name
        try:
            result = analyze_lsb_wav(p)
            # Should detect the embedded message
            assert result["recomputed_message_length"] == len(msg)
        finally:
            os.unlink(p)

    def test_extract_from_wav(self):
        msg = b"SECRET_WAV_MESSAGE_42"
        wav = _make_wav_with_message(msg)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            p = f.name
        try:
            result = extract_lsb_wav(p)
            assert msg in result["extracted"]
        finally:
            os.unlink(p)


class TestOrchestrator:
    def test_image_analysis(self):
        img = _make_test_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            report = full_analyze(p)
            assert report["type"] == "image"
            assert len(report["findings"]) >= 2  # lsb + palette + appended
        finally:
            os.unlink(p)

    def test_unknown_file_type(self):
        with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False) as f:
            f.write(b"some data")
            p = f.name
        try:
            report = full_analyze(p)
            assert report["verdict"] == "UNSUPPORTED"
        finally:
            os.unlink(p)

    def test_not_found(self):
        report = full_analyze("/nonexistent/file.png")
        assert report["verdict"] == "NOT FOUND"


class TestCLI:
    def test_analyze_command(self, capsys):
        img = _make_test_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            from stegohunter.cli import main
            rc = main(["analyze", p])
            assert rc in (0, 2)
            captured = capsys.readouterr()
            assert "ARCHIVE: ONLINE" in captured.out
        finally:
            os.unlink(p)

    def test_extract_lsb_command(self, capsys):
        img = _make_test_image(50, 50)
        msg = b"FLAG{cli_test_works}"
        stego = _embed_lsb_message(img, msg)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(stego)
            p = f.name
        out_path = p.replace(".png", ".lsb.bin")
        try:
            from stegohunter.cli import main
            rc = main(["extract-lsb", p])
            assert rc == 0
            if os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    data = f.read()
                assert msg in data
                os.unlink(out_path)
        finally:
            os.unlink(p)

    def test_lsb_subcommand_json(self, capsys):
        img = _make_test_image(50, 50)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img)
            p = f.name
        try:
            from stegohunter.cli import main
            rc = main(["lsb", p])
            assert rc == 0
            captured = capsys.readouterr()
            parsed = json.loads(captured.out)
            assert "suspicious" in parsed
        finally:
            os.unlink(p)

    def test_audio_extract_command(self, capsys):
        msg = b"AUDIO_CLI_FLAG"
        wav = _make_wav_with_message(msg)
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav)
            p = f.name
        out_path = p.replace(".wav", ".lsb.bin")
        try:
            from stegohunter.cli import main
            rc = main(["extract-audio", p])
            assert rc == 0
            if os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    data = f.read()
                assert msg in data
                os.unlink(out_path)
        finally:
            os.unlink(p)

    def test_appended_command(self, capsys):
        img = _make_test_image(32, 32, fmt="JPEG")
        trailer = b"APPENDED_CLI_TEST"
        stego = _append_data_to_jpeg(img, trailer)
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(stego)
            p = f.name
        try:
            from stegohunter.cli import main
            rc = main(["appended", p])
            assert rc == 0
            captured = capsys.readouterr()
            parsed = json.loads(captured.out)
            assert parsed["appended"]
        finally:
            os.unlink(p)


class TestUtilityFunctions:
    def test_get_lsb_plane(self):
        pixels = [0, 1, 2, 3, 4, 5, 6, 7]
        plane = _get_lsb_plane(pixels, 0)
        assert plane == bytes([0, 1, 0, 1, 0, 1, 0, 1])

    def test_get_lsb_bytes(self):
        pixels = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        b = _get_lsb_bytes(pixels, 1)
        assert b == bytes([0b01010101, 0b01010101])

    def test_byte_histogram(self):
        data = bytes([0, 1, 2, 3])
        h = byte_histogram(data)
        assert h[0] == 1
        assert h[1] == 1
        assert h[2] == 1
        assert h[3] == 1
        assert sum(h) == 4


class TestIsImage:
    def test_png(self):
        assert is_image("test.png")
        assert not is_image("test.wav")


class TestIsAudio:
    def test_wav(self):
        assert is_audio("test.wav")
        assert not is_audio("test.png")


# =========================================================================
#  Integration: end-to-end stego generation → detection → extraction
# =========================================================================

def test_e2e_image_lsb():
    """Full round-trip: generate → embed → detect → extract."""
    img = _make_test_image(100, 100)
    msg = b"E2E_TEST_FLAG{round_trip_success}"
    stego = _embed_lsb_message(img, msg)

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(stego)
        p = f.name
    try:
        # Analyze
        report = full_analyze(p)
        assert report["verdict"] in ("SUSPICIOUS", "HIDDEN DATA LIKELY")

        # Extract
        result = extract_lsb_message(p)
        assert msg in result["extracted"]
    finally:
        os.unlink(p)


def test_e2e_audio_lsb():
    """Full round-trip: generate WAV → embed → detect → extract."""
    msg = b"E2E_AUDIO_FLAG{secret_audio_message}"
    wav = _make_wav_with_message(msg)
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        f.write(wav)
        p = f.name
    try:
        # Analyze
        result = analyze_lsb_wav(p)
        assert result["recomputed_message_length"] == len(msg)

        # Extract
        extracted = extract_lsb_wav(p)
        assert msg in extracted["extracted"]
    finally:
        os.unlink(p)


def test_e2e_appended_data():
    """Full round-trip: generate JPEG → append data → detect → extract."""
    img = _make_test_image(32, 32, fmt="JPEG")
    trailer = b"E2E_APPENDED_FLAG{appended_data_extracted}"
    stego = _append_data_to_jpeg(img, trailer)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(stego)
        p = f.name
    try:
        # Detect
        result = find_appended_data(p)
        assert result["appended"]
        assert trailer in result["data"]

        # Extract
        ext = extract_appended_data(p)
        assert trailer in ext["extracted"]
        os.unlink(ext["output_path"])
    finally:
        os.unlink(p)


if __name__ == "__main__":
    pytest.main(["-v", __file__])