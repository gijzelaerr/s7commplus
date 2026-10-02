"""Tests for conservative bit-lane tracing of generated transforms."""

from __future__ import annotations

import ast
import random

import pytest

from old.family0._generated import monolith5
from tools.trace_v1_session_key_bits import _evaluate, trace_output_bits


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis


def test_fixed_shifts_masks_and_power_of_two_multiplication() -> None:
    cases = {
        "src_dwords[3] << 2 & 0xC": {2: {(3, 0)}, 3: {(3, 1)}},
        "_shr(src_dwords[3], 2) & 3": {0: {(3, 2)}, 1: {(3, 3)}},
        "src_dwords[3] * 2 & 6": {1: {(3, 0)}, 2: {(3, 1)}},
        "src_dwords[3] & 0": {},
        "src_dwords[3] | 0xFFFFFFFF": {},
    }
    for expression, expected in cases.items():
        result = _evaluate(ast.parse(expression, mode="eval").body, {})
        assert {bit: set(value.sources) for bit, value in enumerate(result) if value.sources} == expected


@pytest.mark.parametrize("expression", ["src_dwords[0] * 3", "src_dwords[0] << src_dwords[1]", "abs(src_dwords[0])"])
def test_unsupported_operations_fail_closed(expression: str) -> None:
    with pytest.raises(ValueError):
        _evaluate(ast.parse(expression, mode="eval").body, {})


def test_monolith5_bit_trace_excludes_fixed_padding_bits() -> None:
    for word in range(12):
        bits = trace_output_bits(5, word)
        assert len(bits) == 32
        assert all(not bits[bit] for bit in (0, 1, 30, 31))
        assert all(bits[bit] for bit in range(3, 30))
        assert all(source_bit in range(32) for sources in bits for _, source_bit in sources)


def test_monolith5_perturbations_never_escape_bit_trace() -> None:
    rng = random.Random(0x5E5510)
    source = bytearray(rng.randbytes(216))
    baseline = bytearray(48)
    monolith5.execute(baseline, source)
    dependencies = [trace_output_bits(5, word) for word in range(12)]
    for word in range(12):
        value = int.from_bytes(baseline[word * 4 : word * 4 + 4], "little")
        assert value & 0xC0000003 == 0
    assert int.from_bytes(baseline[24:28], "little") & 4 == 0

    for _ in range(100):
        source_bit = rng.randrange(len(source) * 8)
        changed_source = bytearray(source)
        changed_source[source_bit // 8] ^= 1 << (source_bit % 8)
        changed = bytearray(48)
        monolith5.execute(changed, changed_source)
        for word in range(12):
            value = int.from_bytes(changed[word * 4 : word * 4 + 4], "little")
            assert value & 0xC0000003 == 0
        changed_bits = int.from_bytes(baseline, "little") ^ int.from_bytes(changed, "little")
        for output_bit in range(384):
            if changed_bits & (1 << output_bit):
                assert (source_bit // 32, source_bit % 32) in dependencies[output_bit // 32][output_bit % 32]
