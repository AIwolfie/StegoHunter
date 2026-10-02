"""Orchestrator — run the full detection suite on a file."""

from __future__ import annotations

import os

from .analyzers import analyze_lsb, analyze_palette, find_appended_data
from .audio import analyze_lsb_wav

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp"}
AUDIO_EXTS = {".wav"}


def is_image(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in IMAGE_EXTS


def is_audio(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in AUDIO_EXTS


def full_analyze(path: str) -> dict:
    """Run every applicable analysis module on ``path``.

    Returns a report dict with:
      - ``file``: path
      - ``type``: "image" | "audio" | "unknown"
      - ``findings``: list of per-module results
      - ``verdict``: "CLEAN" | "SUSPICIOUS" | "HIDDEN DATA LIKELY"
    """
    if not os.path.exists(path):
        return {"file": path, "type": "unknown", "findings": [], "verdict": "NOT FOUND"}

    ext = os.path.splitext(path)[1].lower()
    findings: list[dict] = []
    suspicious_flags: list[bool] = []

    if ext in IMAGE_EXTS:
        findings.append({"module": "lsb", **analyze_lsb(path)})
        findings.append({"module": "palette", **analyze_palette(path)})
        suspicious_flags.append(findings[-1]["suspicious"])
        suspicious_flags.append(findings[-2]["suspicious"])

    elif ext in AUDIO_EXTS:
        findings.append({"module": "audio_lsb", **analyze_lsb_wav(path)})
        suspicious_flags.append(findings[-1]["suspicious"])

    else:
        return {"file": path, "type": "unknown", "findings": [], "verdict": "UNSUPPORTED"}

    # Appended data scan applies to any file
    appended = find_appended_data(path)
    findings.append({"module": "appended", **appended})
    suspicious_flags.append(appended.get("appended", False))

    n_suspicious = sum(1 for f in suspicious_flags if f)
    if n_suspicious >= 2:
        verdict = "HIDDEN DATA LIKELY"
    elif n_suspicious == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "file": path,
        "type": "image" if ext in IMAGE_EXTS else "audio",
        "findings": findings,
        "verdict": verdict,
        "n_suspicious": n_suspicious,
    }