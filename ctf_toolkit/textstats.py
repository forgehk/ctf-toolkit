"""Text statistics: Shannon entropy, letter frequency."""

from __future__ import annotations

import math

def shannon_entropy(s: str) -> float:
    """Bits-per-character Shannon entropy.

    Useful heuristic:
      - English text ≈ 4.0-4.5
      - Base64 ≈ 5.5-6.0
      - Random ≈ 7.5+
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def frequency_table(s: str, *, normalize: bool = True) -> dict[str, float]:
    """Return letter frequencies sorted by frequency desc.

    Args:
        s: input text.
        normalize: if True, return probabilities (0..1); if False, raw counts.
    """
    counts: dict[str, int] = {}
    for c in s.upper():
        if "A" <= c <= "Z":
            counts[c] = counts.get(c, 0) + 1
    if not counts:
        return {}
    if not normalize:
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
    total = sum(counts.values())
    return {k: v / total for k, v in sorted(counts.items(), key=lambda kv: -kv[1])}
