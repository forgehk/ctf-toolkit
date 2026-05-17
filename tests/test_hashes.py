"""Tests for hash utilities."""

from pathlib import Path

from ctf_toolkit.hashes import compute, crack, identify

def test_identify_md5():
    assert "MD5" in identify("5d41402abc4b2a76b9719d911017c592")

def test_identify_sha256():
    assert "SHA-256" in identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

def test_identify_bcrypt_prefix():
    assert "bcrypt" in identify("$2b$12$Nq3Y3Y5Y5Y5Y5Y5Y5Y5Y5OAbCdEfGhIjKlMnOpQrStUvWxYzAbCdE")

def test_compute_md5_known():
    assert compute("md5", "password") == "5f4dcc3b5aa765d61d8327deb882cf99"

def test_compute_sha256_known():
    assert compute("sha256", "abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_crack_finds_password(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("apple\nhello\npassword\nbanana\n")
    digest = compute("md5", "password")
    assert crack("md5", digest, wordlist) == "password"

def test_crack_returns_none_when_not_found(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("apple\nbanana\n")
    digest = compute("md5", "carrot")
    assert crack("md5", digest, wordlist) is None
