"""Exhaustive lane proofs and independent full-output checks for named gates."""

from __future__ import annotations

import json
import random
import struct
from collections import Counter
from pathlib import Path

import pytest

from s7commplus.session_auth.family0._generated import monolith5
from tools.monolith5_gate_model import evaluate_lane, execute_words
from tools.recover_monolith5_gates import format_formula, recover_model

_ROOT = Path(__file__).resolve().parents[1]


def test_span_gate_model_is_exactly_regenerated_from_luts() -> None:
    saved = json.loads((_ROOT / "tools/monolith5_gate_model.json").read_text(encoding="utf-8"))
    assert recover_model() == saved
    assert Counter(function["combine"] for function in saved["functions"]) == {
        "xor3": 15,
        "majority": 15,
        "or3": 1,
        "not_all_equal": 1,
    }
    assert {function["gate"] for function in saved["functions"]} == {"choose", "majority"}


def test_all_gate_functions_match_every_lut_row_in_parallel() -> None:
    """Pack 32 distinct truth rows per call, covering all 16,384 rows exactly."""
    luts = json.loads((_ROOT / "tools/monolith5_model.json").read_text(encoding="utf-8"))["luts"]
    for function_id, encoded in enumerate(luts):
        table = int(encoded, 16)
        for start in range(0, 512, 32):
            source = [
                sum(((row >> variable) & 1) << lane for lane, row in enumerate(range(start, start + 32))) for variable in range(9)
            ]
            assert evaluate_lane(function_id, source) == (table >> start) & 0xFFFFFFFF


def test_gate_model_matches_upstream_known_answer() -> None:
    fixtures = _ROOT / "tests/fixtures/family0/monoliths"
    source = (fixtures / "monolith5-src.bin").read_bytes()
    expected = (fixtures / "monolith5-dst.bin").read_bytes()
    assert struct.pack("<12I", *execute_words(struct.unpack("<54I", source))) == expected


def test_gate_model_matches_generated_for_structured_and_random_words() -> None:
    rng = random.Random(0x5A6A7E)
    sources = [[0] * 54, [0xFFFFFFFF] * 54, [0xAAAAAAAA] * 54, [0x55555555] * 54]
    sources.extend([[rng.getrandbits(32) for _ in range(54)] for _ in range(100)])
    # A one-bit source near both ends exercises cached lane selectors and padding.
    for word in (0, 17, 18, 35, 36, 53):
        for bit in (0, 1, 2, 29, 30, 31):
            source = [0] * 54
            source[word] = 1 << bit
            sources.append(source)
    for source in sources:
        generated = bytearray(48)
        monolith5.execute(generated, struct.pack("<54I", *source))
        assert struct.pack("<12I", *execute_words(source)) == generated


def test_formula_names_span_gates_and_symmetric_combine() -> None:
    model = recover_model()
    formula = format_formula(model, 0)
    assert "s0 = choose(x0, x1, x2)" in formula
    assert "s1 = choose(x3, x4, x5)" in formula
    assert "s2 = choose(x6, x7, x8)" in formula
    assert "F0(x0, ..., x8) = not_all_equal(s0, s1, s2)" in formula
    assert "NOT" in format_formula(model, 1)


def test_gate_model_validates_source_and_function_ids() -> None:
    with pytest.raises(ValueError, match="54 source words"):
        execute_words([0] * 53)
    with pytest.raises(ValueError, match="nine input words"):
        evaluate_lane(0, [0] * 8)
    with pytest.raises(ValueError, match="0..31"):
        evaluate_lane(32, [0] * 9)
    with pytest.raises(ValueError, match="0..31"):
        format_formula(recover_model(), -1)
