"""Exact symbolic and independent vector checks for the compact Monolith5 model."""

from __future__ import annotations

import ast
import itertools
import json
import random
import struct
from pathlib import Path

import pytest

from old.family0._generated import monolith5
from tools.monolith5_model import execute_words
from tools.recover_monolith5 import BDD, recover_model


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests/fixtures/family0/monoliths"


def _bdd_value(bdd: BDD, node: int, values: dict[tuple[int, int], int]) -> int:
    while node >= 2:
        variable, low, high = bdd.nodes[node]
        node = high if values[bdd.refs[variable]] else low
    return node


def test_bdd_interpreter_matches_small_exhaustive_expression() -> None:
    refs = [(0, 0), (0, 1), (1, 1)]
    bdd = BDD(refs)
    expression = ast.parse("~((src_dwords[0] << 1) & src_dwords[1]) ^ _shr(src_dwords[0], 1)", mode="eval").body
    output = bdd.expression(expression, {})
    for assignment in range(8):
        source0 = (assignment & 1) | (assignment & 2)
        source1 = ((assignment >> 2) & 1) << 1
        expected = (~((source0 << 1) & source1) ^ (source0 >> 1)) & 0xFFFFFFFF
        values = {ref: (assignment >> index) & 1 for index, ref in enumerate(refs)}
        actual = sum(_bdd_value(bdd, node, values) << bit for bit, node in enumerate(output))
        assert actual == expected


def test_compact_model_is_exactly_regenerated_from_generated_source() -> None:
    saved = json.loads((_ROOT / "tools/monolith5_model.json").read_text(encoding="utf-8"))
    recovered = json.loads(json.dumps(recover_model()))
    assert recovered == saved
    assert len(saved["luts"]) == 32
    assert len(saved["entries"]) == 168


def test_recovered_lane_functions_are_symmetric_across_input_spans() -> None:
    saved = json.loads((_ROOT / "tools/monolith5_model.json").read_text(encoding="utf-8"))
    for encoded in saved["luts"]:
        table = int(encoded, 16)
        for index in range(512):
            spans = [(index >> (3 * span)) & 7 for span in range(3)]
            expected = (table >> index) & 1
            for order in itertools.permutations(range(3)):
                permuted = sum(spans[order[span]] << (3 * span) for span in range(3))
                assert ((table >> permuted) & 1) == expected


def test_compact_model_matches_upstream_known_answer() -> None:
    source = (_FIXTURES / "monolith5-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith5-dst.bin").read_bytes()
    words = execute_words(struct.unpack("<54I", source))
    assert struct.pack("<12I", *words) == expected


def test_compact_model_matches_generated_on_random_inputs() -> None:
    rng = random.Random(0x5E5510)
    for _ in range(100):
        source = rng.randbytes(216)
        generated = bytearray(48)
        monolith5.execute(generated, source)
        words = execute_words(struct.unpack("<54I", source))
        assert struct.pack("<12I", *words) == generated


def test_compact_model_requires_complete_source() -> None:
    with pytest.raises(ValueError, match="54 source words"):
        execute_words([0] * 53)
