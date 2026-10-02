"""stegohunter/audio — audio steganalysis modules."""

from .wav import analyze_lsb_wav, extract_lsb_wav

__all__ = ["analyze_lsb_wav", "extract_lsb_wav"]