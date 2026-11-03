"""Batch Directory Triage scanner for StegoHunter."""

from __future__ import annotations

import concurrent.futures
import os
from typing import Callable, Optional

from .orchestrator import full_analyze, IMAGE_EXTS, AUDIO_EXTS
from .reporting import generate_html_report

SUPPORTED_EXTS = IMAGE_EXTS | AUDIO_EXTS


def find_files(target_dir: str, recursive: bool = True) -> list[str]:
    """Discover all supported image and audio files in target directory."""
    matched = []
    if not os.path.exists(target_dir):
        return matched

    if os.path.isfile(target_dir):
        ext = os.path.splitext(target_dir)[1].lower()
        if ext in SUPPORTED_EXTS:
            return [target_dir]
        return []

    if recursive:
        for root, _, files in os.walk(target_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUPPORTED_EXTS:
                    matched.append(os.path.join(root, file))
    else:
        for item in os.listdir(target_dir):
            p = os.path.join(target_dir, item)
            if os.path.isfile(p):
                ext = os.path.splitext(item)[1].lower()
                if ext in SUPPORTED_EXTS:
                    matched.append(p)

    return sorted(matched)


def triage_directory(
    target_dir: str,
    recursive: bool = True,
    max_workers: int = 4,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict]:
    """Run full steganalysis across all supported files in directory using a worker pool."""
    files = find_files(target_dir, recursive=recursive)
    total = len(files)
    if total == 0:
        return []

    results: list[dict] = []
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(full_analyze, f): f for f in files}
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            completed += 1
            if progress_callback:
                progress_callback(completed, total, file_path)
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                results.append({
                    "file": file_path,
                    "type": "unknown",
                    "findings": [],
                    "verdict": "ERROR",
                    "error": str(e),
                })

    # Sort results by verdict severity: HIDDEN DATA LIKELY -> SUSPICIOUS -> CLEAN -> others
    verdict_rank = {"HIDDEN DATA LIKELY": 0, "SUSPICIOUS": 1, "CLEAN": 2}
    results.sort(key=lambda r: (verdict_rank.get(r.get("verdict"), 3), r.get("file", "")))
    return results
