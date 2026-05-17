"""Tests for text statistics."""

import pytest

from ctf_toolkit.textstats import frequency_table, shannon_entropy

def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0

def test_entropy_uniform_is_log2_size():
    # 4 unique chars, uniformly distributed -> 2 bits/char.
    assert shannon_entropy("abcdabcd") == pytest.approx(2.0)

def test_entropy_constant_is_zero():
    assert shannon_entropy("aaaa") == 0.0

def test_entropy_higher_for_diverse_text():
    # Repetitive single-character pattern has near-zero entropy.
    # Mixed alphabetic text has substantially higher entropy.
    repetitive = "aaaaaaaaaaaaaaaaaaaaaa"
    diverse = "the quick brown fox jumps over the lazy dog"
    assert shannon_entropy(diverse) > shannon_entropy(repetitive)

def test_entropy_random_bytes_high():
    # Full 256-char alphabet would give ~8 bits/char. Even 64-char range gives ~6.
    big_alphabet = "".join(chr(i) for i in range(33, 127))
    assert shannon_entropy(big_alphabet) > 6.0

def test_frequency_table_letters_only():
    table = frequency_table("Hello, World!")
    assert table["L"] == pytest.approx(3 / 10)
    assert "!" not in table  # punctuation excluded
