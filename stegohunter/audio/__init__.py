"""stegohunter/audio — audio steganalysis modules."""

from .wav import analyze_lsb_wav, extract_lsb_wav
from .spectrogram import generate_spectrogram, compute_spectrogram

__all__ = ["analyze_lsb_wav", "extract_lsb_wav", "generate_spectrogram", "compute_spectrogram"]