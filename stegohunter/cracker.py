"""Stego Passphrase Cracker — multi-threaded dictionary attack runner."""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from typing import Callable, Iterable, Optional

from .analyzers.appended import find_appended_data

DEFAULT_WORDLIST = [
    "",
    "password",
    "123456",
    "12345678",
    "admin",
    "secret",
    "stego",
    "passphrase",
    "hunter",
    "flag",
    "root",
    "toor",
    "qwerty",
    "letmein",
    "welcome",
    "hidden",
    "guest",
    "master",
    "dragon",
    "football",
    "monkey",
    "shadow",
]


def _try_crack_zip(zip_bytes: bytes, password: str) -> Optional[bytes]:
    """Attempt extracting the first file from a zip using a password."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            pwd_bytes = password.encode("utf-8")
            for name in zf.namelist():
                try:
                    data = zf.read(name, pwd=pwd_bytes)
                    if data:
                        return data
                except (RuntimeError, zipfile.BadZipFile):
                    continue
    except Exception:
        pass
    return None


def _try_crack_steghide(file_path: str, password: str) -> Optional[bytes]:
    """Attempt extraction using external steghide binary."""
    with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
        out_path = tmp_out.name

    try:
        cmd = [
            "steghide",
            "extract",
            "-sf",
            file_path,
            "-p",
            password,
            "-xf",
            out_path,
            "-f",
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if res.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, "rb") as f:
                extracted = f.read()
            return extracted
    except Exception:
        pass
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except Exception:
                pass
    return None


def _try_crack_keyed_lsb(raw_lsb_bytes: bytes, password: str) -> Optional[bytes]:
    """Attempt decrypting XOR/hash-keyed LSB steganography."""
    if len(raw_lsb_bytes) < 8 or not password:
        return None

    # Derive repeating keystream using SHA-256
    key = hashlib.sha256(password.encode("utf-8")).digest()
    decrypted = bytearray(len(raw_lsb_bytes))
    for i, b in enumerate(raw_lsb_bytes):
        decrypted[i] = b ^ key[i % len(key)]

    # Check if decrypted starts with printable text or length prefix
    # 1. Length-prefix ASCII
    if len(decrypted) >= 8:
        length = int.from_bytes(decrypted[:4], "big")
        if 0 < length <= min(len(decrypted) - 4, 100_000):
            payload = decrypted[4 : 4 + length]
            printable = sum(32 <= b < 127 for b in payload) / len(payload)
            if printable > 0.8:
                return bytes(payload)

    # 2. Direct printable ASCII string
    printable_count = sum(32 <= b < 127 for b in decrypted[:64])
    if printable_count >= 24:
        # Null-terminated or trimmed
        null_pos = decrypted.find(b"\x00")
        if null_pos > 0:
            return bytes(decrypted[:null_pos])
        return bytes(decrypted[:128])

    return None


import io


def crack_passphrase(
    file_path: str,
    wordlist_path: Optional[str] = None,
    max_workers: int = 8,
    output_path: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> dict:
    """Run a multi-threaded passphrase attack on a target stego file.

    Returns:
      - ``success``: bool
      - ``password``: Optional[str]
      - ``tool``: str
      - ``attempts``: int
      - ``extracted_bytes``: Optional[bytes]
      - ``output_path``: Optional[str]
    """
    has_steghide = shutil.which("steghide") is not None
    has_outguess = shutil.which("outguess") is not None

    # Load wordlist
    words: list[str] = []
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip("\r\n")
                if w:
                    words.append(w)
    else:
        words = list(DEFAULT_WORDLIST)

    # Check if file has appended ZIP data
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    appended = find_appended_data(file_path)
    zip_bytes: Optional[bytes] = None
    if appended.get("appended") and appended.get("contains_zip"):
        zip_bytes = appended.get("data")
    elif file_bytes.startswith(b"PK\x03\x04"):
        zip_bytes = file_bytes

    # Read LSB bytes for keyed LSB stego
    lsb_raw: Optional[bytes] = None
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".png", ".bmp", ".webp", ".jpg", ".jpeg"):
        try:
            from PIL import Image
            img = Image.open(file_path).convert("RGB")
            flat = [v for p in img.get_flattened_data() for v in p]
            bits = [v & 1 for v in flat]
            # Pack first 4096 bytes
            out_b = bytearray()
            for i in range(0, min(len(bits) - 7, 32768), 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                out_b.append(byte)
            lsb_raw = bytes(out_b)
        except Exception:
            pass

    found_password: Optional[str] = None
    extracted_data: Optional[bytes] = None
    tool_detected = "unknown"
    stop_event = threading.Event()
    attempts_lock = threading.Lock()
    attempts_count = 0

    def worker_attempt(pwd: str) -> bool:
        nonlocal found_password, extracted_data, tool_detected, attempts_count
        if stop_event.is_set():
            return False

        with attempts_lock:
            attempts_count += 1
            cur_attempts = attempts_count

        if progress_callback and (cur_attempts % 25 == 0 or cur_attempts == len(words)):
            progress_callback(cur_attempts, len(words), pwd)

        # 1. Try ZIP if archive data is present
        if zip_bytes:
            extracted = _try_crack_zip(zip_bytes, pwd)
            if extracted:
                found_password = pwd
                extracted_data = extracted
                tool_detected = "zip"
                stop_event.set()
                return True

        # 2. Try steghide if installed
        if has_steghide:
            extracted = _try_crack_steghide(file_path, pwd)
            if extracted:
                found_password = pwd
                extracted_data = extracted
                tool_detected = "steghide"
                stop_event.set()
                return True

        # 3. Try keyed LSB
        if lsb_raw:
            extracted = _try_crack_keyed_lsb(lsb_raw, pwd)
            if extracted:
                found_password = pwd
                extracted_data = extracted
                tool_detected = "keyed_lsb"
                stop_event.set()
                return True

        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker_attempt, word) for word in words]
        for f in concurrent.futures.as_completed(futures):
            if stop_event.is_set():
                break

    wrote_file: Optional[str] = None
    if found_password is not None and extracted_data:
        if output_path is None:
            base = os.path.splitext(file_path)[0]
            output_path = f"{base}_cracked.bin"
        with open(output_path, "wb") as f:
            f.write(extracted_data)
        wrote_file = output_path

    return {
        "success": found_password is not None,
        "password": found_password,
        "tool": tool_detected,
        "attempts": attempts_count,
        "total_words": len(words),
        "extracted_bytes_len": len(extracted_data) if extracted_data else 0,
        "output_path": wrote_file,
    }
