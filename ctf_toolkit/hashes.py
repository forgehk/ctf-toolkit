"""Hash identification, computation, and wordlist cracking."""

from __future__ import annotations

import hashlib
from pathlib import Path

# (regex of valid char class, length, name)
HASH_HINTS: list[tuple[str, int, str]] = [
    ("hex", 32, "MD5"),
    ("hex", 40, "SHA-1"),
    ("hex", 56, "SHA-224"),
    ("hex", 64, "SHA-256"),
    ("hex", 96, "SHA-384"),
    ("hex", 128, "SHA-512"),
    ("hex", 32, "NTLM (Windows)"),
    ("hex", 40, "RIPEMD-160"),
    ("b64", 24, "MD5 (base64)"),
    ("b64", 44, "SHA-256 (base64)"),
]

def identify(digest: str) -> list[str]:
    """Return all likely algorithm names for a given digest string."""
    d = digest.strip()
    length = len(d)
    is_hex = all(c in "0123456789abcdefABCDEF" for c in d)
    is_b64 = all(c.isalnum() or c in "+/=" for c in d)
    candidates: list[str] = []
    for kind, expected_len, name in HASH_HINTS:
        if length != expected_len:
            continue
        if kind == "hex" and is_hex:
            candidates.append(name)
        elif kind == "b64" and is_b64 and not is_hex:
            # Hex strings also pass b64 charset; only suggest b64 when NOT hex.
            candidates.append(name)
    # Special prefixes
    if d.startswith("$2a$") or d.startswith("$2b$") or d.startswith("$2y$"):
        candidates.append("bcrypt")
    if d.startswith("$argon2"):
        candidates.append("argon2")
    return candidates or ["unknown (length=%d, hex=%s)" % (length, is_hex)]

SUPPORTED_ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")

def compute(algo: str, text: str) -> str:
    """Compute hex digest of `text` with given algorithm."""
    algo = algo.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(f"unsupported algo: {algo}. Supported: {SUPPORTED_ALGOS}")
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()

def crack(algo: str, target: str, wordlist: Path) -> str | None:
    """Dictionary attack — try each word in `wordlist`, return matching plaintext or None."""
    target_lower = target.lower()
    with open(wordlist, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            word = line.rstrip("\n")
            if not word:
                continue
            if compute(algo, word).lower() == target_lower:
                return word
    return None
