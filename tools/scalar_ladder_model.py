"""Compact checkout-only scalar ladder under modular-shadow semantics.

The recovered source encodings establish this model conditionally on the
affine setup shadow and Q=0, not on exact compatibility arithmetic. Inputs
must be synthetic/public; never use this diagnostic as runtime cryptography.
"""

from __future__ import annotations

from tools.recover_scalar_curve import CURVE_B
from tools.recover_scalar_encodings import recover_all, scalar_xor_mask
from tools.recover_scalar_shadow import MODULUS

Point = tuple[int, int]


def double(point: Point) -> Point:
    x, z = point
    x2, z2 = x * x % MODULUS, z * z % MODULUS
    return (
        (x2 * x2 + 2 * x2 * z2 - 8 * CURVE_B * x * z * z2 + z2 * z2) % MODULUS,
        4 * z * (x * x2 - x * z2 + CURVE_B * z * z2) % MODULUS,
    )


def step(first: Point, second: Point, difference_x: int, bit: int) -> tuple[Point, Point]:
    if bit not in (0, 1):
        raise ValueError("ladder bit must be zero or one")
    x, z = first
    u, v = second
    h2 = (x * v - u * z) ** 2 % MODULUS
    numerator = (2 * (x * v + u * z) * (x * u - z * v) + 4 * CURVE_B * z * z * v * v - difference_x * h2) % MODULUS
    addition = numerator, h2
    return (double(first), addition) if bit == 0 else (addition, double(second))


def model(x: int, y: int, prng1: int, scalar: int) -> tuple[int, int]:
    """Return tail (Z,N), retaining the source's projective scaling modulo p."""
    if any(type(value) is not int or not 0 <= value < 1 << 160 for value in (x, y, prng1, scalar)):
        raise ValueError("four unsigned 160-bit synthetic inputs required")
    scale_y, r = (y | 4) % MODULUS, (prng1 | 4) % MODULUS
    first, second = (x * scale_y % MODULUS, scale_y), (r * r % MODULUS, 0)
    flips = (False,) + tuple(row.bit_flip for row in recover_all()) + (True,)
    for index, flip in enumerate(flips):
        first, second = step(first, second, x % MODULUS, ((scalar >> (159 - index)) & 1) ^ int(flip))
    return second[1], second[0]


def effective_scalar(scalar: int) -> int:
    if type(scalar) is not int or not 0 <= scalar < 1 << 160:
        raise ValueError("unsigned 160-bit selector required")
    return scalar ^ scalar_xor_mask()
