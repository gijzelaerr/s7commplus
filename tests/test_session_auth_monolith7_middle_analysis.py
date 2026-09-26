"""Exact symbolic and differential checks for the Monolith7 middle model."""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith7
from tools.decompose_boolean_polynomial import CORE_FORMULAS
from tools.monolith7_middle_model import execute_words
from tools.recover_monolith7_middle import recover_model

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests/fixtures/family0/monoliths"


def test_middle_model_is_exactly_regenerated_from_generated_source() -> None:
    saved = json.loads((_ROOT / "tools/monolith7_middle_model.json").read_text(encoding="utf-8"))
    assert saved == json.loads(json.dumps(recover_model()))
    assert len(saved["functions"]) == 68
    assert len(saved["bits"]) == 96
    assert max(function["inputs"] for function in saved["functions"]) == 14
    assert len(saved["kernels"]) == 8
    assert all((kernel["inputs"], frozenset(kernel["terms"])) in CORE_FORMULAS for kernel in saved["kernels"])
    assert max(len(function["steps"]) for function in saved["functions"]) == 5
    assert max(len(function["terms"]) for function in saved["functions"]) == 4


def test_middle_model_matches_upstream_known_answer() -> None:
    source = (_FIXTURES / "monolith7-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith7-dst.bin").read_bytes()
    words = execute_words(struct.unpack("<24I", source))
    assert struct.pack("<3I", *words) == expected[3 * 4 : 6 * 4]


@pytest.mark.parametrize("seed", [0, 0x7E11])
def test_middle_model_matches_generated_on_random_inputs(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(100):
        source = rng.randbytes(96)
        destination = bytearray(144)
        monolith7.execute(destination, source)
        words = execute_words(struct.unpack("<24I", source))
        assert struct.pack("<3I", *words) == destination[3 * 4 : 6 * 4]


def test_middle_model_requires_complete_source() -> None:
    with pytest.raises(ValueError, match="24 source words"):
        execute_words([0] * 23)
