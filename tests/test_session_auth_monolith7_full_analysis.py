"""Exact regeneration and complete differential checks for Monolith7."""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith7
from tools.monolith7_full_model import execute_words
from tools.recover_monolith7_full import recover_model

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests/fixtures/family0/monoliths"


def test_full_model_is_exactly_regenerated_from_generated_source() -> None:
    saved = json.loads((_ROOT / "tools/monolith7_full_model.json").read_text(encoding="utf-8"))
    assert saved == json.loads(json.dumps(recover_model()))
    assert saved["output_words"] == list(range(36))
    assert len(saved["bits"]) == 1152
    nodes = saved["nodes"]
    assert len(nodes) == len({tuple(node) for node in nodes})
    for identifier, (variable, low, high) in enumerate(nodes, start=2):
        assert 0 <= variable < 22
        assert 0 <= low < identifier and 0 <= high < identifier
        assert low != high
        for child in (low, high):
            if child >= 2:
                assert nodes[child - 2][0] > variable
    for function in saved["functions"]:
        assert 0 <= function["root"] < len(nodes) + 2


def test_full_model_matches_upstream_known_answer() -> None:
    source = (_FIXTURES / "monolith7-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith7-dst.bin").read_bytes()
    assert struct.pack("<36I", *execute_words(struct.unpack("<24I", source))) == expected


@pytest.mark.parametrize("seed", [0, 0x7F011])
def test_full_model_matches_generated_on_random_inputs(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(100):
        source = rng.randbytes(96)
        destination = bytearray(144)
        monolith7.execute(destination, source)
        assert struct.pack("<36I", *execute_words(struct.unpack("<24I", source))) == destination


@pytest.mark.parametrize("value", [0, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555])
def test_full_model_matches_generated_on_uniform_words(value: int) -> None:
    source = struct.pack("<24I", *([value] * 24))
    destination = bytearray(144)
    monolith7.execute(destination, source)
    assert struct.pack("<36I", *execute_words([value] * 24)) == destination


def test_full_model_requires_complete_source() -> None:
    with pytest.raises(ValueError, match="24 source words"):
        execute_words([0] * 23)
