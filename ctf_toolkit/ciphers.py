"""Classical ciphers and breakers."""

from __future__ import annotations

import string

# Approximate English letter frequency (Cornell, 0..1 scale).
ENGLISH_FREQ = {
    "A": 0.082, "B": 0.015, "C": 0.028, "D": 0.043, "E": 0.130, "F": 0.022,
    "G": 0.020, "H": 0.061, "I": 0.070, "J": 0.0015, "K": 0.0077, "L": 0.040,
    "M": 0.024, "N": 0.067, "O": 0.075, "P": 0.019, "Q": 0.00095, "R": 0.060,
    "S": 0.063, "T": 0.091, "U": 0.028, "V": 0.0098, "W": 0.024, "X": 0.0015,
    "Y": 0.020, "Z": 0.00074,
}

def caesar(text: str, shift: int) -> str:
    """Apply a Caesar shift. Preserves case; non-letters pass through."""
    shift %= 26
    out: list[str] = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(c)
    return "".join(out)

def caesar_brute(text: str) -> tuple[int, str, list[tuple[int, str, float]]]:
    """Try all 26 shifts; rank by chi-square distance from English frequency.

    Returns (best_shift, best_plaintext, all_candidates_sorted).
    """
    candidates: list[tuple[int, str, float]] = []
    for shift in range(26):
        candidate = caesar(text, shift)
        score = _english_score(candidate)
        candidates.append((shift, candidate, score))
    candidates.sort(key=lambda t: t[2])
    best_shift, best_text, _ = candidates[0]
    return best_shift, best_text, candidates

def _english_score(text: str) -> float:
    """Chi-square distance from English letter frequency. Lower = more English-like."""
    letters = [c for c in text.upper() if "A" <= c <= "Z"]
    if not letters:
        return float("inf")
    n = len(letters)
    score = 0.0
    for letter, expected_prob in ENGLISH_FREQ.items():
        observed = letters.count(letter)
        expected = expected_prob * n
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score

def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    """Vigenère cipher (key applies only to letters)."""
    if not key:
        raise ValueError("vigenere: key cannot be empty")
    key_clean = [c.upper() for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("vigenere: key must contain letters")
    out: list[str] = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key_clean[ki % len(key_clean)]) - ord("A")
            if decrypt:
                shift = -shift
            base = ord("A") if c.isupper() else ord("a")
            out.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)

def xor_decrypt(hex_data: str, key: str) -> bytes:
    """XOR a hex-encoded string with a repeating key. Returns raw bytes."""
    data = bytes.fromhex(hex_data.replace(" ", ""))
    key_bytes = key.encode()
    if not key_bytes:
        raise ValueError("xor: key cannot be empty")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

def xor_encrypt(plaintext: str, key: str) -> str:
    """XOR a plaintext with a repeating key. Returns hex."""
    key_bytes = key.encode()
    if not key_bytes:
        raise ValueError("xor: key cannot be empty")
    return bytes(
        b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(plaintext.encode())
    ).hex()

def atbash(text: str) -> str:
    """Atbash: A↔Z, B↔Y, ..."""
    out: list[str] = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            out.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            out.append(c)
    return "".join(out)

def letter_freq(text: str) -> dict[str, int]:
    """Letter-frequency table (case-insensitive, letters only)."""
    out: dict[str, int] = {c: 0 for c in string.ascii_uppercase}
    for c in text.upper():
        if c in out:
            out[c] += 1
    return out
