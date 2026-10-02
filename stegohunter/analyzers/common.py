"""entropy — shared utility for statistical analysis."""

import math
from collections import Counter


def entropy(data: bytes, base: int = 2) -> float:
    """Shannon entropy of a byte sequence. Higher values → more random-looking data."""
    if not data:
        return 0.0
    c = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log(count / total, base) for count in c.values())


def byte_histogram(data: bytes, bins: int = 256) -> list[int]:
    """Return histogram of byte values (length ``bins``)."""
    h = [0] * bins
    for b in data:
        h[b] += 1
    return h