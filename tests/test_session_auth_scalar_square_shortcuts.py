"""Exact small-output square lifts, including zero and source-domain controls."""

import random
from collections.abc import Callable
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference

P = rules.MODULUS


def omitted_lift(a: int, lift_a: Callable[[], bool]) -> bool:
    return a >= 7


def test_small_and_large_square_boundaries_match_the_fold_oracle() -> None:
    values = list(range(47)) + [47, 48, P - 1, P, P + 1, P + 6, P + 46]
    for raw in values:
        expected = exact.multiply(raw, raw)
        if expected % P <= 46:
            tag = rules.square_lift(raw % P, lambda: raw >= P)
            assert expected == expected % P + P * tag


def test_threshold_settles_the_square_without_a_callback() -> None:
    def unexpected() -> bool:
        raise AssertionError("unneeded square input lift")

    assert rules.square_lift(P - 1, unexpected)
    for a in range(7):
        assert not rules.square_lift(a, lambda: False)
        assert rules.square_lift(a, lambda: True)


def test_zero_square_retains_p_lift_and_negative_control_loses_it() -> None:
    source = Program(0, 1, 2, 0, (Instruction(0, 0, 1, "square", (Operand("input", 0),), 0),), ((1, Operand("value", 0)),))
    plan = compiler.compile_plan(source)
    for raw, expected in ((0, 0), (P, P), (P + 1, P + 1)):
        result = compiler.evaluate(plan, {0: raw}, square_shortcuts=True)
        assert result.outputs == {1: expected}
        assert result.square_rules == result.square_lift_queries == 1
    with patch.object(rules, "square_lift", omitted_lift):
        assert compiler.evaluate(plan, {0: P}, square_shortcuts=True).outputs == {1: 0}


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_source_branches_preserve_outputs_and_carry_trace(cap: int) -> None:
    rng = random.Random(747160)
    for stage in recover():
        samples = [{s: v for s in stage.inputs} for v in (1, P, P + 1)]
        samples.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, cap, boolean_corrections=True)
            for state in samples:
                expected, events = evaluate_stage(stage.index, state, bit)
                result = compiler.evaluate(plan, state, stage.index, bit, square_shortcuts=True)
                assert result.outputs == expected
                assert result.defects == events


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_complete_output_and_every_boundary_are_preserved(cap: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    selector = scalar_xor_mask()
    baseline, old = compiler.full_output(x, y, 0, selector, cap, boolean_corrections=True, demand_guards=True)
    actual, new = compiler.full_output(
        x, y, 0, selector, cap, boolean_corrections=True, demand_guards=True, square_shortcuts=True
    )
    assert (
        actual
        == baseline
        == reference(bytes(20), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little")).destination
    )
    assert tuple(r.outputs for r in new) == tuple(r.outputs for r in old)


def test_actual_square_rule_ast_has_four_unsat_source_obligations() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_square_shortcuts import prove

    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 4
    with patch.object(rules, "square_lift", omitted_lift):
        wrong = prove()
    assert not wrong["full_proof"] and any(row["result"] == "sat" for row in wrong["obligations"])


def test_unknown_and_invalid_timeout_are_not_proofs() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_square_shortcuts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        report = prove()
    assert not report["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive solver timeout"):
            prove(timeout)
