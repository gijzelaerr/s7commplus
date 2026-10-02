"""GCM's GHASH multiplication, with Shoup's 8-bit tables (HarpoS7's HarpoHash).

This is the GF(2^128) multiplication of AES-GCM (NIST SP 800-38D). Blocks are
16 bytes read big endian in GCM's reflected bit order: the most significant
bit of the first byte is the coefficient of x^0, so multiplying by x is a
right shift, reduced by ``0xE1 << 120`` when a bit falls off the end.

- ``times_x`` multiplies a block by x (HarpoS7's ``Lut1``).
- ``multiplication_table`` builds the 4 KB table whose entry ``i`` is the
  byte ``i`` (as the first byte of a block) times the key ``H``
  (``GenerateLookupTable``).
- ``multiply`` multiplies a block by ``H`` one byte at a time, from the last
  byte to the first: ``z = z * x^8 ^ table[byte]``, where ``z * x^8`` shifts
  the byte that falls off back in through ``REDUCTION_TABLE``
  (``HarpoHash.Hash``).

``REDUCTION_TABLE`` holds, for each byte ``i``, the 16-bit reduction of ``i``
shifted out of the block, stored big endian (HarpoS7's ``LutSeed``). Tests pin
all of these against a textbook GHASH multiply and HarpoS7's vectors.

Ported from HarpoS7 (MIT) — ``HarpoS7.Aes.HarpoHash`` and
``HarpoS7.Aes.AesConsts``.
"""

from __future__ import annotations

BLOCK_SIZE = 16
TABLE_SIZE = 256 * BLOCK_SIZE

#: GCM's reduction constant: x^128 = 1 + x + x^2 + x^7 in reflected order.
_R = 0xE1 << 120


def _reduction(byte: int) -> int:
    """The 16 bits that reduce ``byte`` after it is shifted out of the low end of a block."""
    reduction = 0
    for bit in range(8):
        if byte >> bit & 1:
            reduction ^= 0xE100 >> (7 - bit)
    return reduction


_REDUCTION = tuple(_reduction(byte) for byte in range(256))

#: The 256 reductions as big-endian 16-bit values.
REDUCTION_TABLE = b"".join(value.to_bytes(2, "big") for value in _REDUCTION)


def _times_x(value: int) -> int:
    return value >> 1 ^ (_R if value & 1 else 0)


def _multiply(a: int, b: int) -> int:
    """``a * b`` in GCM's field, bit by bit from ``a``'s x^0 coefficient."""
    product = 0
    for bit in range(127, -1, -1):
        if a >> bit & 1:
            product ^= b
        b = _times_x(b)
    return product


def _check_length(name: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")


def times_x(block: bytes) -> bytes:
    """``block * x`` for a 16-byte block."""
    _check_length("block", block, BLOCK_SIZE)
    return _times_x(int.from_bytes(block, "big")).to_bytes(BLOCK_SIZE, "big")


def multiplication_table(key: bytes) -> bytes:
    """The 4096-byte Shoup table for ``key``: entry ``i`` is ``(i << 120) * key``."""
    _check_length("key", key, BLOCK_SIZE)
    h = int.from_bytes(key, "big")
    return b"".join(_multiply(byte << 120, h).to_bytes(BLOCK_SIZE, "big") for byte in range(256))


def multiply(block: bytes, table: bytes) -> bytes:
    """``block * H`` for the ``H`` whose ``multiplication_table`` is ``table``."""
    _check_length("block", block, BLOCK_SIZE)
    _check_length("table", table, TABLE_SIZE)
    z = 0
    for byte in reversed(block):
        z = (z >> 8) ^ (_REDUCTION[z & 0xFF] << 112) ^ int.from_bytes(table[byte * BLOCK_SIZE : (byte + 1) * BLOCK_SIZE], "big")
    return z.to_bytes(BLOCK_SIZE, "big")
