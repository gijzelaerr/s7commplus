"""Transform12 on plain integers: the same tape as ``transform12``, without packing.

Every context slot and constant row is a canonical packing of an unsigned
160-bit integer (``prepare`` inverts ``finalize`` on it), so each BigInt
primitive reduces to the integer formula below, derived from
``big_int_transforms``; tests pin both against it.
"""

from __future__ import annotations

import struct

from ._generated.data import TRANSFORM12_BIG_INT_DATA, TRANSFORM12_METADATA

SLOTS = 149
_BITS = 160
_LIMIT = 1 << _BITS
_MASK = _LIMIT - 1
_FOLD = 47
_LOW128 = (1 << 128) - 1
_WORD = 0xFFFFFFFF


def encode(value: int) -> bytes:
    """Canonical packing: five 28-bit lanes and one 20-bit lane, each shifted left by two."""
    return struct.pack("<6I", *(((value >> (28 * lane)) & 0x0FFFFFFF) << 2 for lane in range(6)))


def decode(packed: bytes | bytearray | memoryview) -> int:
    """Inverse of ``encode`` for canonical packings."""
    return sum((word >> 2) << (28 * lane) for lane, word in enumerate(struct.unpack("<6I", bytes(packed[:24]))))


def add(a: int, b: int) -> int:
    """BigIntAddition: on overflow add 47 to the low 128 bits, and 94 more if that carry is lost."""
    total = a + b
    if total < _LIMIT:
        return total
    corrected = (total & _LOW128) + _FOLD
    low = corrected & _LOW128
    if corrected >> 128:
        low = (low & ~_WORD) | ((low + 2 * _FOLD) & _WORD)
    return (total & _MASK & ~_LOW128) | low


def subtract(a: int, b: int) -> int:
    """BigIntSubtraction: negative differences lose an extra 47, then wrap to 160 bits."""
    difference = a - b
    return (difference - (_FOLD if difference < 0 else 0)) & _MASK


def multiply(a: int, b: int) -> int:
    """BigIntMultiplication/Square: fold the overflow twice, then a low-word-only correction."""
    product = a * b
    for _ in range(2):
        if product >= _LIMIT:
            product = (product & _MASK) + (product >> _BITS) * _FOLD
    if product >= _LIMIT:
        product = (product & ~_WORD) | ((product + _FOLD) & _WORD)
    return product & _MASK


_CONSTANTS = tuple(
    decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) for offset in range(0, len(TRANSFORM12_BIG_INT_DATA) - 23, 24)
)
# (opcode, destination, first source, second source) per tape word; sources >= 0x100 are constant rows.
_TAPE = tuple(
    (word >> 30, (word >> 22) & 0xFF, (word >> 11) & 0x3FF, word & 0x3FF)
    for (word,) in struct.iter_unpack("<I", TRANSFORM12_METADATA[: len(TRANSFORM12_METADATA) // 4 * 4])
)


def execute(values: list[int], index: int, count: int) -> None:
    """Run ``count`` tape instructions from ``index`` over the integer context ``values``."""
    constants = _CONSTANTS
    for opcode, destination, first, second in _TAPE[index : index + count]:
        a = values[first] if first < 0x100 else constants[first - 0x100]
        b = values[second] if second < 0x100 else constants[second - 0x100]
        if opcode == 0:
            values[destination] = multiply(a, b)
        elif opcode == 1:
            values[destination] = multiply(a, a)
        elif opcode == 2:
            values[destination] = add(a, b)
        else:
            values[destination] = subtract(a, b)
