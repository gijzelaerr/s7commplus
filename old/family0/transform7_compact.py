"""Transform7 on plain integers: proven setup arithmetic, then the Transform12 tape.

Byte-for-byte equivalent to ``transform7.execute``, which is kept, unexecuted,
as the reference the analysis tools instrument; see ARCHITECTURE.md.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

from . import transform12_compact
from ._generated.data import TRANSFORM7_DATA
from ._generated.data._constants import TRANSFORM7_COUNTS_INTS, TRANSFORM7_INDEXES_INTS
from .big_int_transforms import big_int_addition
from .monolith_wrappers import ReadableBuffer, monolith4_with_copy, monolith6_with_copy, monolith7_with_copy

DESTINATION_SIZE = 72

_P = (1 << 160) - 47
_HALF = (_P + 1) // 2
_PAYLOAD_MASK = (1 << 168) - 1
# Decoded payload of the bundled span TRANSFORM7_DATA[0x48:0x90]; TRANSFORM7_DATA[:0x48] decodes to zero.
_BUNDLED_PAYLOAD = 479351431067838523670377406553314858552643643568
_FINAL_SPAN = bytes(TRANSFORM7_DATA[0x90:0xD8])


class Span(NamedTuple):
    """A decoded monolith operand: 168 payload bits plus a boundary bit worth (p+1)/2."""

    payload: int
    boundary: int = 0


Pair = tuple[Span, Span]
_ZERO = Span(0)


def _carry_save(a: Span, b: Span, c: Span) -> tuple[int, int]:
    """Return (sum, carry) with sum + 2*carry = the three spans' total."""
    boundaries = a.boundary + b.boundary + c.boundary
    parity = a.payload ^ b.payload ^ c.payload
    half = _HALF * (boundaries & 1)
    majority = ((a.payload & b.payload | a.payload & c.payload | b.payload & c.payload) << 1) | int(boundaries >= 2)
    return parity ^ half ^ majority, (parity & half) | (parity & majority) | (half & majority)


def _halve(a: Span, b: Span, c: Span) -> Pair:
    """Decoded Monolith6."""
    total, carry = _carry_save(a, b, c)
    return Span(total >> 1, total & 1), Span(carry)


def _quarter(pair: Pair, plain: int) -> Pair:
    """Decoded Monolith3; the plain operand becomes the span (plain >> 1, plain & 1)."""
    return _halve(*pair, Span(plain >> 1, plain & 1))


def _add(pair: Pair) -> Span:
    """Decoded Monolith4."""
    a, b = pair
    return Span(a.payload + b.payload + (a.boundary & b.boundary), a.boundary ^ b.boundary)


def _lanes(value: int) -> bytes:
    return struct.pack("<6I", *(((value >> (28 * lane)) & 0x0FFFFFFF) << 2 for lane in range(6)))


def _merge(context: list[int], slot: int, single: Span, pair: Pair) -> None:
    """Monolith5's two carry-save streams, merged into a context slot by BigIntAddition."""
    total, carry = _carry_save(single, *pair)
    merged = bytearray(24)
    big_int_addition(merged, _lanes(total & _PAYLOAD_MASK), _lanes((carry << 1) & _PAYLOAD_MASK))
    context[slot] = transform12_compact.decode(merged)


def _setup(context: list[int], x: int, y: int, r: int) -> None:
    """Write context slots 46, 70, 48 and 94, following the original call order."""
    y, r = y | 4, r | 4
    bundled = (_ZERO, Span(_BUNDLED_PAYLOAD))
    pair0 = _quarter(bundled, r)
    pair1 = _quarter(bundled, y)
    pair2 = _quarter(pair0, x)
    pair3 = _quarter(pair2, y)
    _merge(context, 46, _add(pair3), pair3)
    pair6 = _quarter(pair3, r)
    pair10 = _halve(_add(pair6), *pair1)
    pair12 = _halve(_add(pair0), *pair2)
    pair14 = _halve(_add(pair12), *pair1)
    _merge(context, 70, _add(pair14), pair14)
    pair18 = _halve(_add(pair10), *pair14)
    _merge(context, 48, _add(pair18), pair18)
    _merge(context, 94, _ZERO, _quarter((_ZERO, _ZERO), x << 2))


def _monolith7(packed: ReadableBuffer, span: ReadableBuffer) -> tuple[bytearray, bytearray]:
    first, second = bytearray(72), bytearray(72)
    monolith7_with_copy(first, second, packed, span)
    return first, second


def _monolith6(a: ReadableBuffer, b: ReadableBuffer, c: ReadableBuffer) -> tuple[bytearray, bytearray]:
    first, second = bytearray(72), bytearray(72)
    monolith6_with_copy(first, second, a, b, c)
    return first, second


def _monolith4(pair: tuple[ReadableBuffer, ReadableBuffer]) -> bytearray:
    total = bytearray(72)
    monolith4_with_copy(total, *pair)
    return total


def execute(destination: bytearray, prng1: bytearray, prng2: bytearray, source: bytes) -> None:
    x, y = int.from_bytes(source[:20], "little"), int.from_bytes(source[20:40], "little")
    r = int.from_bytes(prng1[:20], "little")
    context = [0] * transform12_compact.SLOTS
    _setup(context, x, y, r)

    # 160 stages select on the scalar prng2 from its top bit down; 89 more on (prng1 | 4) from bit 0.
    scalar, tail_bits = int.from_bytes(prng2[:20], "little"), r | 4
    for stage in range(249):
        bit = (scalar >> (159 - stage)) & 1 if stage < 160 else (tail_bits >> (stage - 160)) & 1
        index = 2 * stage + bit
        transform12_compact.execute(context, TRANSFORM7_INDEXES_INTS[index], TRANSFORM7_COUNTS_INTS[index])

    def packed(number: int) -> bytes:
        return transform12_compact.encode(context[number])

    base = _monolith4(_monolith7(packed(27), _FINAL_SPAN))
    c, d = _monolith7(packed(27), base)
    first = _monolith4((c, d))
    common = _monolith4(_monolith7(packed(61), first))
    total = _monolith4(_monolith7(packed(97), common))
    monolith4_with_copy(destination, *_monolith6(base, *_monolith6(total, c, d)))
