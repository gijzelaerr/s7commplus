"""Vector tests for the Family-0 transforms.

Vendored from ``HarpoS7.Family0.Tests/Transforms/TransformTests.cs``
plus the corresponding ``Blobs/Transforms`` fixtures.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from s7commplus.v1_session_key.real_plc import checksum
from old.family0 import checksum_transform, lut_generator, transform13
from old.family0 import pre_seed_transform as old_pre_seed_transform
from old.family0 import key_derivation_transform as old_key_derivation_transform


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_FIXTURES = Path(__file__).parent / "fixtures" / "family0" / "transforms"


def test_pre_seed_transform_vector() -> None:
    src = (_FIXTURES / "transform1-src.bin").read_bytes()
    expected = (_FIXTURES / "transform1-dst.bin").read_bytes()
    dst = bytearray(old_pre_seed_transform.DESTINATION_SIZE)
    old_pre_seed_transform.execute(dst, src)
    assert bytes(dst) == expected


def test_key_derivation_transform_vector() -> None:
    src = (_FIXTURES / "transform2-src.bin").read_bytes()
    expected = (_FIXTURES / "transform2-dst.bin").read_bytes()
    dst = bytearray(old_key_derivation_transform.DESTINATION_SIZE)
    old_key_derivation_transform.execute(dst, src)
    assert bytes(dst) == expected


def test_lut_generator_vector() -> None:
    src = (_FIXTURES / "transform3-src.bin").read_bytes()
    expected = (_FIXTURES / "transform3-dst.bin").read_bytes()
    dst = bytearray(lut_generator.DESTINATION_SIZE)
    lut_generator.execute(dst, src)
    assert bytes(dst) == expected


def test_checksum_transform_vector() -> None:
    key = (_FIXTURES / "transform4-key.bin").read_bytes()
    lut = (_FIXTURES / "transform4-lut.bin").read_bytes()
    expected = (_FIXTURES / "transform4-dst.bin").read_bytes()
    dst = bytearray(checksum_transform.DESTINATION_SIZE)
    checksum_transform.execute(dst, key, lut)
    assert bytes(dst) == expected


def _clmul_mod(a: int, b: int) -> int:
    """Schoolbook carry-less product, then long division by the polynomial."""
    product = 0
    for bit in range(b.bit_length()):
        if b >> bit & 1:
            product ^= a << bit
    for bit in range(product.bit_length() - 1, 127, -1):
        if product >> bit & 1:
            product ^= checksum.POLYNOMIAL << (bit - 128)
    return product


def test_checksum_vector_is_a_field_multiplication_by_the_table_seed() -> None:
    key = (_FIXTURES / "transform4-key.bin").read_bytes()
    lut = (_FIXTURES / "transform4-lut.bin").read_bytes()
    expected = (_FIXTURES / "transform4-dst.bin").read_bytes()
    product = checksum.multiply(int.from_bytes(key, "little"), int.from_bytes(lut[16:32], "little"))
    assert product.to_bytes(16, "little") == expected


def test_checksum_transform_with_the_generated_table_is_multiply() -> None:
    rng = random.Random(4700)
    for h, x in [(1, 1), (1 << 127, 2), ((1 << 128) - 1, (1 << 128) - 1)] + [
        (rng.getrandbits(128), rng.getrandbits(128)) for _ in range(100)
    ]:
        lut = bytearray(lut_generator.DESTINATION_SIZE)
        lut_generator.execute(lut, h.to_bytes(16, "little"))
        dst = bytearray(checksum_transform.DESTINATION_SIZE)
        checksum_transform.execute(dst, x.to_bytes(16, "little"), bytes(lut))
        assert int.from_bytes(dst, "little") == checksum.multiply(x, h) == _clmul_mod(x, h)


def test_checksum_polynomial_is_irreducible() -> None:
    """Rabin's test for degree 128: x^(2^128) = x, and gcd(x^(2^64) - x, f) = 1."""
    polynomial = checksum.POLYNOMIAL

    def square_x(times: int) -> int:
        value = 2
        for _ in range(times):
            value = checksum.multiply(value, value)
        return value

    def gcd(a: int, b: int) -> int:
        while b:
            while a.bit_length() >= b.bit_length():
                a ^= b << (a.bit_length() - b.bit_length())
            a, b = b, a
        return a

    assert square_x(128) == 2
    assert gcd(polynomial, square_x(64) ^ 2) == 1


@pytest.mark.parametrize("value", [0, 1, 1 << 127])
def test_checksum_multiply_identities(value: int) -> None:
    assert checksum.multiply(value, 1) == value
    assert checksum.multiply(value, 0) == 0
    assert checksum.multiply(1 << 127, 2) == checksum.POLYNOMIAL ^ (1 << 128)


def test_transform13_vector() -> None:
    src = (_FIXTURES / "transform13-src.bin").read_bytes()
    expected = (_FIXTURES / "transform13-dst.bin").read_bytes()
    dst = bytearray(transform13.DESTINATION_SIZE)
    transform13.execute(dst, src)
    assert bytes(dst) == expected
