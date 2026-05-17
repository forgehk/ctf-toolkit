"""Tests for encoders and decoders."""

import pytest

from ctf_toolkit.encoders import decode, encode

@pytest.mark.parametrize(
    "fmt,plain,encoded",
    [
        ("b64", "hello world", "aGVsbG8gd29ybGQ="),
        ("b32", "hello", "NBSWY3DP"),
        ("hex", "abc", "616263"),
        ("url", "hi there!", "hi%20there%21"),
        ("rot13", "Hello", "Uryyb"),
        ("binary", "Ab", "01000001 01100010"),
    ],
)
def test_roundtrip(fmt: str, plain: str, encoded: str) -> None:
    assert encode(fmt, plain) == encoded
    assert decode(fmt, encoded) == plain

def test_morse_encode():
    assert encode("morse", "SOS") == "... --- ..."

def test_b64_decode_tolerates_missing_padding():
    assert decode("b64", "aGVsbG8") == "hello"

def test_unknown_format_raises():
    with pytest.raises(ValueError):
        encode("klingon", "x")
    with pytest.raises(ValueError):
        decode("klingon", "x")
