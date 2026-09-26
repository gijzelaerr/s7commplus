"""Exact symbolic checks and differential tests for the Monolith7 tail model."""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith7
from tools.analyze_symbolic_monolith import analyze_output_bit
from tools.monolith7_tail_model import execute_words
from tools.recover_monolith7_tail import recover_model

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests/fixtures/family0/monoliths"


def test_tail_model_is_exactly_regenerated_from_generated_source() -> None:
    saved = json.loads((_ROOT / "tools/monolith7_tail_model.json").read_text(encoding="utf-8"))
    assert saved == json.loads(json.dumps(recover_model()))
    assert len(saved["functions"]) == 63
    assert len(saved["bits"]) == 96


def test_tail_model_matches_upstream_known_answer() -> None:
    source = (_FIXTURES / "monolith7-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith7-dst.bin").read_bytes()
    words = execute_words(struct.unpack("<24I", source))
    assert struct.pack("<3I", *words) == expected[15 * 4 : 18 * 4]


def test_tail_model_matches_generated_on_random_inputs() -> None:
    rng = random.Random(0x7E11)
    for _ in range(100):
        source = rng.randbytes(96)
        destination = bytearray(144)
        monolith7.execute(destination, source)
        words = execute_words(struct.unpack("<24I", source))
        assert struct.pack("<3I", *words) == destination[15 * 4 : 18 * 4]


@pytest.mark.parametrize("word,bit", [(0, 0), (15, 20), (18, 10), (33, 20)])
def test_symbolic_analysis_matches_generated_bits(word: int, bit: int) -> None:
    analysis = analyze_output_bit(7, word, bit)
    assert set(analysis.essential_source_bits) <= set(analysis.candidate_source_bits)
    rng = random.Random(0x7E11 + word * 32 + bit)
    for _ in range(10):
        source = rng.randbytes(96)
        destination = bytearray(144)
        monolith7.execute(destination, source)
        source_words = dict(enumerate(struct.unpack("<24I", source)))
        expected = (struct.unpack_from("<I", destination, word * 4)[0] >> bit) & 1
        assert analysis.evaluate(source_words) == expected


def test_symbolic_analysis_rejects_invalid_bit() -> None:
    with pytest.raises(ValueError, match="0..31"):
        analyze_output_bit(7, 15, 32)


def test_tail_model_requires_complete_source() -> None:
    with pytest.raises(ValueError, match="24 source words"):
        execute_words([0] * 23)
