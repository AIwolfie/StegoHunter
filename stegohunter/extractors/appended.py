"""Appended-data extraction — write trailing bytes to a file."""

from __future__ import annotations

import os


def extract_appended_data(
    file_path: str,
    output_path: Optional[str] = None,
    preview_size: int = 1024,
) -> dict:
    """Extract and save data appended after the file's end-of-image marker.

    Returns a dict with extracted bytes and file info.
    """
    from ..analyzers.appended import find_appended_data

    result = find_appended_data(file_path)
    if not result.get("appended"):
        return {"extracted": b"", "appended": False, "output_path": None}

    with open(file_path, "rb") as f:
        data = f.read()
    offset = result["offset"]
    trailing = data[offset:]

    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_appended{ext}"

    with open(output_path, "wb") as f:
        f.write(trailing)

    return {
        "extracted": trailing,
        "appended": True,
        "offset": offset,
        "size": len(trailing),
        "output_path": output_path,
    }