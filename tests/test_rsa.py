"""Tests for RSA attack helpers.

The big vectors are real RSA instances (512-bit primes) generated so that each
weak-parameter condition holds exactly; only the module under test is used to
recover the secret.
"""

import pytest

from ctf_toolkit.rsa import (
    common_modulus_attack,
    egcd,
    integer_nth_root,
    int_to_bytes,
    modinv,
    small_e_attack,
    wiener_attack,
)

# --- helpers ---------------------------------------------------------------

def test_integer_nth_root_exact():
    assert integer_nth_root(27, 3) == (3, True)
    assert integer_nth_root(2 ** 300, 3) == (2 ** 100, True)

def test_integer_nth_root_floor_when_inexact():
    root, exact = integer_nth_root(28, 3)
    assert root == 3 and exact is False

def test_integer_nth_root_edges():
    assert integer_nth_root(0, 5) == (0, True)
    assert integer_nth_root(1, 5) == (1, True)

def test_egcd_bezout_identity():
    g, x, y = egcd(240, 46)
    assert g == 2
    assert 240 * x + 46 * y == g

def test_modinv_roundtrip():
    assert (17 * modinv(17, 3120)) % 3120 == 1

def test_modinv_raises_when_not_coprime():
    with pytest.raises(ValueError):
        modinv(6, 9)

def test_int_to_bytes_roundtrip():
    assert int_to_bytes(int.from_bytes(b"hello", "big")) == b"hello"

# --- small-e / low-exponent ------------------------------------------------

SMALL_E_N = 95923139841174800886345405077814597927095490672615176605715017810324679313788863729906580296682498249767626290561811317788309494194357120034933770872900922345230067233377021375088585999838534092080445988492984166661617124399676227579323227707131154992650479132387376922227523171446430708128865866255700477587
SMALL_E_C = 12026207886496628243170774666511880421591101187760283163896013645264767431852403028324535541536706690152683472608141773157
SMALL_E_M = 22910939699456427372759345257912801850493

def test_small_e_recovers_message():
    m = small_e_attack(3, SMALL_E_N, SMALL_E_C)
    assert m == SMALL_E_M
    assert int_to_bytes(m) == b"CTF{low_exponent}"

def test_small_e_returns_none_when_wrapped():
    # A ciphertext that is not a perfect cube: attack must not apply.
    assert small_e_attack(3, SMALL_E_N, SMALL_E_C + 1) is None

# --- common modulus --------------------------------------------------------

COMMON_N = 172500175658724109038601958232076908775187473525006855368609268070881043612565934070273357790239883854536248161736421958285665795250072540208906157838240407594110180557017154829858495490083349761801915245010826904627918208602000571139082497302023729873922665628056301564223687514963463762719959803276522906313
COMMON_C1 = 3385076584453081051888495094181425373248563260485007606715382097468985772218704464826036129126522220069966983610201884685024203167297125
COMMON_C2 = 7631574785737464487677651954096629227752420228841813858259331187349591753690845548270293355980181000707728473813660041004281718927219976799866807220973138723574863586183412578023439370946366954504923879353933435863713399978125
COMMON_M = 1501491344096844964637549717814087501370192765

def test_common_modulus_recovers_message():
    m = common_modulus_attack(COMMON_N, 3, COMMON_C1, 5, COMMON_C2)
    assert m == COMMON_M
    assert int_to_bytes(m) == b"CTF{common_modulus}"

def test_common_modulus_none_when_exponents_share_factor():
    assert common_modulus_attack(COMMON_N, 4, COMMON_C1, 6, COMMON_C2) is None

# --- Wiener ----------------------------------------------------------------

WIENER_E = 24293140291784436875875955088896577303260831587588118529590306740231793585300627297721832254313196787331826594947056537361360611648591519778228237264598548937545969914125152641738181534205392423455877178307339768969947777232699638488571215543765918841075689315115547955271868279148959578083895906070004323989
WIENER_N = 102504911074682310763288766529585807399422824268664585600186056348412349158187606495845882295754461018624636888920310712239170275477123763672522300313980478647038824002437928377070266203210791744738044963190597229134558877037378517245374777816119221256747273952516038105725478851352340108813375321513446481243
WIENER_D = 16770071641869688208143302236036891002497431872112412735651967494616812950389

def test_wiener_recovers_private_exponent():
    assert wiener_attack(WIENER_E, WIENER_N) == WIENER_D

def test_wiener_returns_none_for_safe_exponent():
    # e = 65537 with a normal-sized d: no small convergent, attack fails cleanly.
    assert wiener_attack(65537, WIENER_N) is None
