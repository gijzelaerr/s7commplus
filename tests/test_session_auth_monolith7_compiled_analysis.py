"""Exact regeneration and differential checks for the compiled Monolith7 model.

Analysis reference only — see MODEL_BENCHMARKS.md for why this is about 20x
slower and 62x larger than generated code and is not used at runtime.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith7
from tools.compile_monolith7 import compile_source
from tools.monolith7_compiled_model import execute_words

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests/fixtures/family0/monoliths"


def test_compiled_model_is_exactly_regenerated_from_the_full_model() -> None:
    """Guards against hand-edits or a stale checked-in file after a model change."""
    target = _ROOT / "tools/monolith7_compiled_model.py"
    assert target.read_text(encoding="utf-8") == compile_source()


def test_compiled_model_matches_upstream_known_answer() -> None:
    source = (_FIXTURES / "monolith7-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith7-dst.bin").read_bytes()
    assert struct.pack("<36I", *execute_words(struct.unpack("<24I", source))) == expected


@pytest.mark.parametrize("seed", [0, 0x7F011])
def test_compiled_model_matches_generated_on_random_inputs(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(100):
        source = rng.randbytes(96)
        destination = bytearray(144)
        monolith7.execute(destination, source)
        assert struct.pack("<36I", *execute_words(struct.unpack("<24I", source))) == destination


@pytest.mark.parametrize("value", [0, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555])
def test_compiled_model_matches_generated_on_uniform_words(value: int) -> None:
    source = struct.pack("<24I", *([value] * 24))
    destination = bytearray(144)
    monolith7.execute(destination, source)
    assert struct.pack("<36I", *execute_words([value] * 24)) == destination


def test_compiled_model_requires_complete_source() -> None:
    with pytest.raises(ValueError, match="24 source words"):
        execute_words([0] * 23)
