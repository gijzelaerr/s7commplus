"""Source theorem replay, nonvacuity, and complete setup induction accounting."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from tools.prove_monolith_setup_invariant import UPPER_ZERO_TRIPLES, allowed_triple, local_queries, prove
from tools.prove_transform7_setup_ranges import (
    OutputBit,
    SetupDAG,
    prove_compositional,
    require_upper_zero,
    setup_invariant_dependency,
)
from tools.recover_monolith4_span_identity import normalized_span


FOLDER = Path(__file__).resolve().parents[1] / "tools"


def raw_bits(words: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(word >> bit & 1 for word in words for bit in range(32))


def test_bundled_spans_satisfy_complete_upper_encoding_and_witness_breaks_it() -> None:
    for offset in (0, 72):
        words = struct.unpack("<18I", transform7.TRANSFORM7_DATA[offset : offset + 72])
        require_upper_zero(raw_bits(words), None, set())
        changed = tuple(word ^ (1 << 9) if i == 17 else word for i, word in enumerate(words))
        assert normalized_span(words) == normalized_span(changed)
        with pytest.raises(ValueError, match="violates"):
            require_upper_zero(raw_bits(changed), None, set())


def test_upper_provenance_and_malformed_constants_fail_closed() -> None:
    span = tuple(OutputBit(3, 18 + bit // 32, bit % 32) for bit in range(576))
    require_upper_zero(span, (3, 1), {3})
    with pytest.raises(ValueError, match="not been established"):
        require_upper_zero(span, (3, 1), set())
    for bits, origin in ((span[:-1], (3, 1)), (span, (3, 0)), (span, (2, 1))):
        with pytest.raises(ValueError):
            require_upper_zero(bits, origin, {2, 3})
    for bits in ((), (0,) * 575, (False,) * 576, (2,) * 576):
        with pytest.raises(ValueError, match="concrete complete"):
            require_upper_zero(bits, None, set())


def test_local_record_has_every_distinct_obligation_and_current_source_pins() -> None:
    dependency = setup_invariant_dependency()
    assert dependency["file"] == "monolith_setup_invariant_proof.json"
    path = FOLDER / dependency["file"]
    assert dependency["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    report = json.loads(path.read_text())
    assert report["expected_stages"] == 73 and report["full_proof"]
    assert len(report["stages"]) == 73
    assert all(row["result"] == "unsat" and row["proved"] for row in report["stages"])
    assert report["upper_zero_triples"] == [list(values) for values in UPPER_ZERO_TRIPLES]
    assert all(len(values) == 4 and len(set(values)) == 4 for values in UPPER_ZERO_TRIPLES)


@pytest.mark.parametrize("mutation", ("duplicate", "table", "source", "models", "incomplete", "sat"))
def test_local_dependency_rejects_invalid_records(mutation: str) -> None:
    report = json.loads((FOLDER / "monolith_setup_invariant_proof.json").read_text())
    if mutation == "duplicate":
        report["stages"][-1] = report["stages"][0]
    elif mutation == "table":
        report["upper_zero_triples"][0][0] = 0
    elif mutation == "source":
        report["source_sha256"]["monolith3.py"] = "0" * 64
    elif mutation == "models":
        report["gate_model_sha256"].clear()
    elif mutation == "incomplete":
        report["full_proof"] = False
    else:
        report["stages"][0]["result"] = "sat"
    with patch("tools.prove_transform7_setup_ranges.json.loads", return_value=report):
        with pytest.raises(ValueError):
            setup_invariant_dependency()


def test_all_local_source_theorems_replay_and_hypotheses_are_satisfiable() -> None:
    z3 = pytest.importorskip("z3")
    for number in (3, 4, 5, 6):
        _, assumptions, _ = local_queries(number)
        solver = z3.Tactic("sat").solver()
        solver.set(timeout=10000)
        solver.add(*assumptions)
        assert solver.check() == z3.sat
    report = prove(timeout_ms=10000)
    assert report["full_proof"]
    assert len(report["stages"]) == 73


def test_compositional_induction_never_expands_global_outputs() -> None:
    pytest.importorskip("z3")
    with patch("tools.prove_transform7_setup_ranges.verify_translation") as controls:
        with patch.object(SetupDAG, "output", side_effect=AssertionError("global DAG expansion is unnecessary")):
            report = prove_compositional()
    controls.assert_called_once_with(8, False)
    assert report["full_proof"] and report["expected_stages"] == 29
    assert report["zero_wrap_calls"] == list(range(23))
    assert report["completed_premerge_slots"] == [46, 48, 70, 94]
    assert report["slot94_exact_input_identity_proved"]
    assert all(row["result"] == "derived" and row["proved"] for row in report["stages"])
    report["kernel_dependencies"] = {str(number): dependency for number, dependency in report["kernel_dependencies"].items()}
    saved = json.loads((FOLDER / "transform7_setup_invariant_proof.json").read_text())
    for key in (
        "source_sha256",
        "data_sha256",
        "kernel_dependencies",
        "local_invariant_dependency",
        "stages",
        "full_proof",
        "zero_wrap_calls",
        "completed_premerge_slots",
        "slot94_exact_input_identity_proved",
    ):
        assert saved[key] == report[key]
    assert saved["translation_controls"] == 8
    for row in report["stages"]:
        if row.get("zero_wrap_derived"):
            assert type(row["maximum_payload"]) is int and 0 <= row["maximum_payload"] < 1 << 166


@pytest.mark.parametrize("number", (3, 6))
def test_first_hidden_condition_alone_is_not_closed(number: int) -> None:
    z3 = pytest.importorskip("z3")
    _, assumptions, queries = local_queries(number)
    stride = 2 + len(UPPER_ZERO_TRIPLES)
    spans = 2 if number == 3 else 3
    solver = z3.Tactic("sat").solver()
    solver.set(timeout=10000)
    # The decoded bound and only the first upper condition are insufficient:
    # missing neighboring conditions permit a genuine source counterexample.
    solver.add(*[assumptions[span * stride + k] for span in range(spans) for k in range(3)])
    if number == 3:
        solver.add(*assumptions[spans * stride :])
    solver.add(queries[1][1])
    assert solver.check() == z3.sat


def test_invalid_proof_inputs_fail_closed() -> None:
    with pytest.raises(ValueError, match="positive"):
        prove(0)
    with pytest.raises(ValueError, match="unsupported"):
        local_queries(7)
    z3 = pytest.importorskip("z3")
    for bits, allowed in (([], (0,)), ([z3.Bool("a")] * 3, ()), ([z3.Bool("a")] * 3, (8,))):
        with pytest.raises(ValueError, match="three bits"):
            allowed_triple(z3, bits, allowed)
