"""Tests for classical ciphers."""

import pytest

from ctf_toolkit.ciphers import (
    atbash,
    caesar,
    caesar_brute,
    vigenere,
    xor_decrypt,
    xor_encrypt,
)

def test_caesar_roundtrip():
    assert caesar("Hello, World!", 13) == "Uryyb, Jbeyq!"
    assert caesar("Uryyb, Jbeyq!", 13) == "Hello, World!"

def test_caesar_brute_finds_english():
    enc = caesar("Attack at dawn the eastern gate must hold", 7)
    shift, plain, _ = caesar_brute(enc)
    assert shift == (26 - 7) % 26
    assert "Attack" in plain or "ATTACK" in plain.upper()

def test_vigenere_encrypt_then_decrypt():
    ct = vigenere("Attack at dawn", key="lemon")
    pt = vigenere(ct, key="lemon", decrypt=True)
    assert pt == "Attack at dawn"

def test_vigenere_empty_key_raises():
    with pytest.raises(ValueError):
        vigenere("hi", key="")

def test_xor_symmetry():
    cipher_hex = xor_encrypt("secret message", "k")
    plain = xor_decrypt(cipher_hex, "k").decode()
    assert plain == "secret message"

def test_atbash_self_inverse():
    assert atbash("Hello") == "Svool"
    assert atbash(atbash("Hello")) == "Hello"
