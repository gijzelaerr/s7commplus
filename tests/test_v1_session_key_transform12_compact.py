"""The integer Transform12 interpreter matches the packed byte-level original."""

from __future__ import annotations

import random

from old.family0 import big_int_operations, big_int_transforms, transform12, transform12_compact
from old.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from old.family0._generated.data._constants import TRANSFORM7_COUNTS_INTS, TRANSFORM7_INDEXES_INTS
import pytest


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

LIMIT = 1 << 160
P = LIMIT - 47


def _prepared(packed: bytes) -> int:
    out = bytearray(20)
    big_int_operations.prepare(out, packed)
    return int.from_bytes(out, "little")


def test_packing_round_trips_through_prepare_and_finalize() -> None:
    rng = random.Random(1216)
    for value in [0, 1, P - 1, P, LIMIT - 1, *(rng.getrandbits(160) for _ in range(500))]:
        packed = transform12_compact.encode(value)
        finalized = bytearray(24)
        big_int_operations.finalize(finalized, value.to_bytes(20, "little"))
        assert bytes(finalized) == packed
        assert _prepared(packed) == transform12_compact.decode(packed) == value


def test_every_constant_row_is_a_canonical_packing() -> None:
    rows = [TRANSFORM12_BIG_INT_DATA[offset : offset + 24] for offset in range(0, len(TRANSFORM12_BIG_INT_DATA) - 23, 24)]
    assert len(rows) == len(transform12_compact._CONSTANTS) == 768
    for row, value in zip(rows, transform12_compact._CONSTANTS):
        assert transform12_compact.encode(value) == row
        assert _prepared(row) == value


def _operand_pairs() -> list[tuple[int, int]]:
    rng = random.Random(1217)
    edges = [0, 1, 46, 47, (1 << 32) - 1, 1 << 32, (1 << 128) - 48, (1 << 128) - 47, 1 << 128, P - 1, P, LIMIT - 1]
    pairs = [(a, b) for a in edges for b in edges]
    # a = 2^160 - x, b = 2^160 - y: multiplication needs its third correction exactly when xy + 2162 >= 47(x + y).
    pairs += [(LIMIT - x, LIMIT - y) for x in range(1, 61) for y in range(1, 61)]
    pairs += [(rng.getrandbits(160), rng.getrandbits(160)) for _ in range(1000)]
    return pairs


def test_primitives_match_the_packed_runtime_including_rare_corrections() -> None:
    third_branch = 0
    for a, b in _operand_pairs():
        packed_a, packed_b = transform12_compact.encode(a), transform12_compact.encode(b)
        for integer, runtime in (
            (transform12_compact.add, big_int_transforms.big_int_addition),
            (transform12_compact.subtract, big_int_transforms.big_int_subtraction),
            (transform12_compact.multiply, big_int_transforms.big_int_multiplication),
        ):
            result = bytearray(24)
            runtime(result, packed_a, packed_b)
            assert bytes(result) == transform12_compact.encode(integer(a, b))
        square = bytearray(24)
        big_int_transforms.big_int_square(square, packed_a)
        assert bytes(square) == transform12_compact.encode(transform12_compact.multiply(a, a))
        x, y = LIMIT - a, LIMIT - b
        third_branch += 0 < x <= 60 and 0 < y <= 60 and x * y + 2162 >= 47 * (x + y)
    assert third_branch > 1000


def test_every_dispatch_alternative_matches_the_packed_interpreter() -> None:
    rng = random.Random(1218)
    initial = [rng.getrandbits(160) for _ in range(transform12_compact.SLOTS)]
    packed = b"".join(transform12_compact.encode(value) for value in initial)
    assert len(packed) == transform12.CONTEXT_SIZE
    for index, count in zip(TRANSFORM7_INDEXES_INTS, TRANSFORM7_COUNTS_INTS):
        expected, actual = bytearray(packed), list(initial)
        transform12.execute(expected, index, count)
        transform12_compact.execute(actual, index, count)
        assert b"".join(transform12_compact.encode(value) for value in actual) == bytes(expected)
