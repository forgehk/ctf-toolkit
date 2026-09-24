"""RSA attack helpers for CTF challenges. Stdlib-only, from first principles.

These break textbook RSA under the classic weak-parameter conditions that
show up in CTFs — a tiny public exponent, one modulus reused across two
exponents, or a small private exponent. None of them threatens correctly
padded RSA; they exist to turn the usual "here is n, e, c" puzzle into a
one-liner.
"""

from __future__ import annotations

import math

__all__ = [
    "integer_nth_root",
    "egcd",
    "modinv",
    "int_to_bytes",
    "small_e_attack",
    "common_modulus_attack",
    "wiener_attack",
]


def integer_nth_root(x: int, n: int) -> tuple[int, bool]:
    """Return (r, exact) where r == floor(x ** (1/n)) and exact says r**n == x.

    Uses integer binary search so it stays exact for arbitrarily large x
    (floats would lose precision well before CTF-sized moduli).
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    if x < 0:
        raise ValueError("x must be non-negative")
    if x in (0, 1):
        return x, True
    lo, hi = 0, 1
    while hi ** n <= x:
        hi <<= 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** n == x


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: return (g, x, y) with a*x + b*y == g == gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m. Raises ValueError if it does not exist."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse for {a} mod {m}")
    return x % m


def int_to_bytes(m: int) -> bytes:
    """Convert a recovered integer plaintext into its big-endian bytes."""
    if m < 0:
        raise ValueError("m must be non-negative")
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")


def small_e_attack(e: int, n: int, c: int) -> int | None:
    """Low-exponent attack: recover m when m**e < n so no modular wrap occurred.

    In that case c == m**e over the integers, so m is the exact integer
    e-th root of c. Returns m, or None if c is not a perfect e-th power
    (meaning the message did wrap and this attack does not apply).
    """
    if e < 1:
        raise ValueError("e must be >= 1")
    if not 0 <= c < n:
        raise ValueError("c must satisfy 0 <= c < n")
    root, exact = integer_nth_root(c, e)
    return root if exact else None


def common_modulus_attack(
    n: int, e1: int, c1: int, e2: int, c2: int
) -> int | None:
    """Common-modulus attack: one message sent to two coprime exponents.

    Given c1 == m**e1 mod n and c2 == m**e2 mod n with gcd(e1, e2) == 1,
    Bezout gives a, b with a*e1 + b*e2 == 1, so
    m == c1**a * c2**b mod n. Negative exponents use the modular inverse
    of the ciphertext. Returns m, or None if the exponents are not coprime.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def _continued_fraction(num: int, den: int) -> list[int]:
    """Continued-fraction expansion [a0, a1, ...] of num/den."""
    terms: list[int] = []
    while den:
        q = num // den
        terms.append(q)
        num, den = den, num - q * den
    return terms


def _convergents(cf: list[int]):
    """Yield successive convergents (numerator, denominator) of a CF."""
    num_prev2, num_prev1 = 0, 1  # h_{-2}, h_{-1}
    den_prev2, den_prev1 = 1, 0  # k_{-2}, k_{-1}
    for a in cf:
        num = a * num_prev1 + num_prev2
        den = a * den_prev1 + den_prev2
        num_prev2, num_prev1 = num_prev1, num
        den_prev2, den_prev1 = den_prev1, den
        yield num, den


def wiener_attack(e: int, n: int) -> int | None:
    """Wiener's attack: recover the private exponent d when d is small.

    Each convergent k/d of e/n is a candidate. For a real one,
    phi = (e*d - 1) / k is an integer and the quadratic
    x**2 - (n - phi + 1)*x + n has integer roots (the primes p, q).
    Returns d, or None if no convergent works (d was not small enough).
    """
    if e < 1 or n < 1:
        raise ValueError("e and n must be positive")
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (n - phi + 1)x + n = 0 for the primes.
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        root, exact = integer_nth_root(disc, 2)
        if exact and (b + root) % 2 == 0:
            return d
    return None
