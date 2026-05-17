"""Encoders and decoders. Stdlib-only."""

from __future__ import annotations

import base64
import binascii
import codecs
import urllib.parse

MORSE_MAP = {
    "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",  "E": ".",
    "F": "..-.", "G": "--.",  "H": "....", "I": "..",   "J": ".---",
    "K": "-.-",  "L": ".-..", "M": "--",   "N": "-.",   "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
    "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----","1": ".----","2": "..---","3": "...--","4": "....-",
    "5": ".....","6": "-....","7": "--...","8": "---..","9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.",
    "!": "-.-.--", "/": "-..-.",  "(": "-.--.",  ")": "-.--.-",
    "&": ".-...",  ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.",  "-": "-....-", "_": "..--.-", '"': ".-..-.",
    "$": "...-..-","@": ".--.-.",
}
MORSE_REVERSE = {v: k for k, v in MORSE_MAP.items()}

def encode(fmt: str, data: str) -> str:
    fmt = fmt.lower()
    if fmt == "b64":
        return base64.b64encode(data.encode()).decode()
    if fmt == "b32":
        return base64.b32encode(data.encode()).decode()
    if fmt == "hex":
        return data.encode().hex()
    if fmt == "url":
        return urllib.parse.quote(data, safe="")
    if fmt == "rot13":
        return codecs.encode(data, "rot_13")
    if fmt == "binary":
        return " ".join(f"{b:08b}" for b in data.encode())
    if fmt == "morse":
        return " ".join(MORSE_MAP[c] for c in data.upper() if c in MORSE_MAP)
    raise ValueError(f"unknown encode format: {fmt!r}")

def decode(fmt: str, data: str) -> str:
    fmt = fmt.lower()
    try:
        if fmt == "b64":
            # Tolerate missing padding by re-padding.
            padded = data + "=" * ((4 - len(data) % 4) % 4)
            return base64.b64decode(padded).decode("utf-8", errors="replace")
        if fmt == "b32":
            padded = data + "=" * ((8 - len(data) % 8) % 8)
            return base64.b32decode(padded.upper()).decode("utf-8", errors="replace")
        if fmt == "hex":
            return bytes.fromhex(data.replace(" ", "")).decode("utf-8", errors="replace")
        if fmt == "url":
            return urllib.parse.unquote(data)
        if fmt == "rot13":
            return codecs.decode(data, "rot_13")
        if fmt == "binary":
            parts = data.split()
            return bytes(int(p, 2) for p in parts).decode("utf-8", errors="replace")
        if fmt == "morse":
            words = data.strip().split("   ")  # 3 spaces between words
            decoded = []
            for word in words:
                letters = word.split()
                decoded.append("".join(MORSE_REVERSE.get(l, "?") for l in letters))
            return " ".join(decoded)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"decode {fmt} failed: {e}") from None
    raise ValueError(f"unknown decode format: {fmt!r}")
