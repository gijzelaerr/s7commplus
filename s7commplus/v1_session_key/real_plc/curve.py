"""The elliptic curve behind SeedTransform, as an x-only Montgomery ladder.

Recovery for issue #54 showed that Transform7 followed by the Monolith1 loop
and Monolith2 is an x-only scalar multiplication on the short Weierstrass
curve ``y^2 = x^3 - x + B`` over ``GF(2^160 - 47)``, whose group has prime
order ``ORDER``:

- only the first 20 bytes of the 40-byte source (its x-coordinate, little
  endian) are used; the other 20 bytes and ``prng1`` only blind the packed
  intermediate representation and never change the decoded value;
- the ladder walks ``prng2 ^ SCALAR_MASK`` from bit 159 down;
- the point at infinity decodes to 0, and every other result is the canonical
  affine x-coordinate, which is what Monolith2 serializes and what
  Monolith8/Transform13 decode from the span.

SeedTransform is therefore an ECDH: the ephemeral ``x(k*G)`` goes into the
blob, and the shared ``x(k*public_key)`` feeds Transform13.

The generated arithmetic is modular except for BigIntSubtraction when a value
below 47 meets a non-canonical representative just below 2^160. Pseudo-random
intermediates hit that with probability around 2^-150 per operation, but
structured sources such as x = 5 do hit it, and the original Transform7 then
returns a point that is not on the correct multiple. The ladder here always
computes the true multiple. Tests pin it to Transform7 on the generator, every
catalogue public key and HarpoS7's known answers, and record the divergence.
"""

from __future__ import annotations

P = (1 << 160) - 47
A = -1
B = 0xFDEC56A0F1A148A7CA6F04463A24F5F56C3F3A4F
ORDER = 0x100000000000000000000F368CDA5CDB2EBFC69C7
# HarpoS7's TRANSFORM7_DATA[0xD8:0x100], as two little-endian 20-byte integers.
GENERATOR_X = 0x7D2ED8E2846E58D74A7A613285471707A39D0C8E
GENERATOR_Y = 0x57A735E99D694CFE6C7FE8F788BCF113CD8C673B
SCALAR_MASK = 0xF8E62E8673B79CA477A1D36333B1C0DE6C706448


def _double(x: int, z: int) -> tuple[int, int]:
    xx, zz = x * x % P, z * z % P
    return (xx - A * zz) ** 2 - 8 * B * x * z * zz, 4 * z * (x * xx + A * x * zz + B * z * zz)


def _add(x1: int, z1: int, x2: int, z2: int, difference: int) -> tuple[int, int]:
    """x(P1 + P2) from x(P1), x(P2) and the affine x(P1 - P2)."""
    cross = x1 * z2 - x2 * z1
    return (
        2 * (x1 * z2 + x2 * z1) * (x1 * x2 + A * z1 * z2) + 4 * B * (z1 * z2) ** 2 - difference * cross * cross,
        cross * cross,
    )


def x_multiply(scalar: int, x: int) -> int:
    """Affine x(scalar * Q) for the point Q with x-coordinate ``x``, or 0 for infinity.

    ``Q`` may lie on the curve or on its quadratic twist. Transform7 always
    walks 160 bits, but leading zero bits leave the ladder at infinity.
    """
    if scalar < 0:
        raise ValueError("scalar must be non-negative")
    x %= P
    low, high = (1, 0), (x, 1)  # (infinity, Q), with high - low = Q throughout
    for bit in range(scalar.bit_length() - 1, -1, -1):
        total = _add(*low, *high, x)
        if (scalar >> bit) & 1:
            low, high = total, _double(*high)
        else:
            low, high = _double(*low), total
        low, high = (low[0] % P, low[1] % P), (high[0] % P, high[1] % P)
    x_out, z_out = low
    return x_out * pow(z_out, -1, P) % P if z_out else 0


def ladder_scalar(prng2: bytes | bytearray) -> int:
    """The scalar Transform7's ladder walks for a 20-byte ``prng2``."""
    return int.from_bytes(prng2[:20], "little") ^ SCALAR_MASK
