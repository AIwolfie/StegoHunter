"""Audio Spectrogram and Frequency Waterfall Generator for acoustic steganography detection."""

from __future__ import annotations

import math
import os
from typing import Optional

import numpy as np
from PIL import Image, ImageDraw

from .wav import _read_wav


def colormap_spectrogram(norm: np.ndarray, scheme: str = "inferno") -> np.ndarray:
    """Apply a colormap to normalized 2D audio magnitude matrix [0.0, 1.0]."""
    v = np.clip(norm, 0.0, 1.0)
    scheme = scheme.lower()

    if scheme == "grayscale":
        val = (v * 255.0).astype(np.uint8)
        return np.stack([val, val, val], axis=-1)

    if scheme == "cyber":
        # Dark Navy -> Neon Cyan -> Electric Magenta
        r = np.clip(np.where(v < 0.5, 0.2 * v, (v - 0.5) * 2.0), 0.0, 1.0)
        g = np.clip(np.where(v < 0.7, v / 0.7, 1.0 - (v - 0.7) / 0.3), 0.0, 1.0)
        b = np.clip(np.where(v < 0.3, v / 0.3 + 0.3, 1.0), 0.0, 1.0)
        rgb = np.stack([r, g, b], axis=-1) * 255.0
        return rgb.astype(np.uint8)

    if scheme == "viridis":
        # Deep Purple -> Teal -> Green -> Bright Yellow
        r = np.clip(np.where(v < 0.5, 0.2 + 0.2 * v, 0.3 + 1.4 * (v - 0.5)), 0.0, 1.0)
        g = np.clip(np.where(v < 0.3, v / 0.3 * 0.4, 0.4 + (v - 0.3) / 0.7 * 0.6), 0.0, 1.0)
        b = np.clip(np.where(v < 0.4, 0.4 + v / 0.4 * 0.4, 0.8 - (v - 0.4) / 0.6 * 0.7), 0.0, 1.0)
        rgb = np.stack([r, g, b], axis=-1) * 255.0
        return rgb.astype(np.uint8)

    # Default: Inferno (Dark Purple -> Crimson -> Orange -> Yellow)
    r = np.clip(np.where(v < 0.25, 0.5 * v / 0.25, 0.5 + 0.5 * (v - 0.25) / 0.75), 0.0, 1.0)
    g = np.clip(np.where(v < 0.4, 0.0, (v - 0.4) / 0.6), 0.0, 1.0)
    b = np.clip(np.where(v < 0.3, v / 0.3, np.where(v < 0.8, 1.0 - (v - 0.3) / 0.5, 0.0)), 0.0, 1.0)
    rgb = np.stack([r, g, b], axis=-1) * 255.0
    return rgb.astype(np.uint8)


def compute_spectrogram(
    samples: np.ndarray,
    n_fft: int = 1024,
    hop_length: int = 512,
) -> np.ndarray:
    """Compute 2D Short-Time Fourier Transform (STFT) normalized magnitude spectrogram."""
    sig = np.asarray(samples, dtype=np.float64)
    if len(sig) < n_fft:
        # Pad with zeros if sample length is smaller than window
        sig = np.pad(sig, (0, n_fft - len(sig)), mode="constant")

    # Hann window
    window = np.hanning(n_fft)

    # Strided frame extraction
    n_frames = 1 + (len(sig) - n_fft) // hop_length
    if n_frames <= 0:
        n_frames = 1
        frames = sig[:n_fft].reshape(1, n_fft)
    else:
        frames = np.lib.stride_tricks.as_strided(
            sig,
            shape=(n_frames, n_fft),
            strides=(sig.strides[0] * hop_length, sig.strides[0]),
        )

    windowed = frames * window

    # Real Fast Fourier Transform (RFFT)
    spectrum = np.fft.rfft(windowed, n=n_fft, axis=1)
    mag = np.abs(spectrum)

    # Convert to decibels (log scale)
    mag_db = 20.0 * np.log10(np.maximum(mag, 1e-6))

    # Normalize between 5th and 99.5th percentiles to enhance visual steganographic contrasts
    p_min = float(np.percentile(mag_db, 5))
    p_max = float(np.percentile(mag_db, 99.5))
    span = p_max - p_min if (p_max - p_min) > 1e-6 else 1.0

    norm = np.clip((mag_db - p_min) / span, 0.0, 1.0)

    # Transpose so x is time and y is frequency (with low frequencies at bottom)
    return np.flipud(norm.T)


def generate_spectrogram(
    audio_path: str,
    output_path: Optional[str] = None,
    colormap: str = "inferno",
    n_fft: int = 1024,
    hop_length: int = 512,
    target_width: int = 1200,
    target_height: int = 600,
) -> tuple[Image.Image, dict]:
    """Generate audio frequency waterfall / spectrogram image from a WAV audio file."""
    audio_data, fmt = _read_wav(audio_path)
    bps = fmt["bits_per_sample"]
    channels = fmt["num_channels"]
    sr = fmt["sample_rate"]
    nbytes = bps // 8

    # Extract raw samples
    raw_samples = []
    for i in range(0, len(audio_data) - nbytes + 1, nbytes):
        raw = audio_data[i : i + nbytes]
        val = int.from_bytes(raw, "little", signed=True)
        raw_samples.append(val)

    if channels > 1:
        # Convert multi-channel audio to mono
        mono_samples = np.mean(
            np.array(raw_samples[: len(raw_samples) // channels * channels]).reshape(-1, channels),
            axis=1,
        )
    else:
        mono_samples = np.array(raw_samples, dtype=np.float64)

    # Compute spectrogram
    spec_norm = compute_spectrogram(mono_samples, n_fft=n_fft, hop_length=hop_length)

    # Apply colormap
    spec_rgb = colormap_spectrogram(spec_norm, scheme=colormap)
    img = Image.fromarray(spec_rgb, mode="RGB")

    # Resize to comfortable analysis dimensions
    h_freq, w_time = spec_norm.shape
    out_w = max(400, min(2400, target_width if target_width else w_time))
    out_h = max(300, min(1200, target_height if target_height else h_freq))
    img_resized = img.resize((out_w, out_h), Image.Resampling.BILINEAR)

    # Overlay frequency / time axis labels
    draw = ImageDraw.Draw(img_resized)
    nyquist_khz = (sr / 2.0) / 1000.0
    duration_sec = len(mono_samples) / sr

    label_top = f"{nyquist_khz:.1f} kHz (Nyquist)"
    label_mid = f"{nyquist_khz / 2.0:.1f} kHz"
    label_bottom = "0 Hz (DC)"
    time_label = f"Duration: {duration_sec:.2f}s | SR: {sr} Hz | FFT: {n_fft}"

    draw.text((10, 8), label_top, fill=(240, 240, 240))
    draw.text((10, out_h // 2), label_mid, fill=(200, 200, 200))
    draw.text((10, out_h - 24), label_bottom, fill=(240, 240, 240))
    draw.text((out_w - len(time_label) * 8 - 15, out_h - 24), time_label, fill=(220, 220, 220))

    if output_path is None:
        base = os.path.splitext(audio_path)[0]
        output_path = f"{base}_spectrogram.png"

    img_resized.save(output_path)

    stats = {
        "output_path": output_path,
        "sample_rate": sr,
        "duration_seconds": round(duration_sec, 2),
        "total_samples": len(mono_samples),
        "fft_bins": n_fft // 2 + 1,
        "time_frames": spec_norm.shape[1],
        "nyquist_khz": round(nyquist_khz, 2),
        "colormap": colormap,
    }

    return img_resized, stats
