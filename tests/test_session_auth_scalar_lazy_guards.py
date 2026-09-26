"""Lazy exact carry decisions: callback demand, source controls and SMT."""

from collections.abc import Callable
from unittest.mock import patch

import pytest

from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage

P = rules.MODULUS
LOW = rules.arithmetic.LOW_LIMIT


def unexpected_callback() -> bool:
    raise AssertionError("unnecessary guard lift dependency")


def without_two_lifts(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return (
        a + b >= MODULUS + 47
        and (a + b) % arithmetic.LOW_LIMIT >= arithmetic.LOW_LIMIT - 47
        or a + b >= arithmetic.LOW_LIMIT
        and (a + b) % arithmetic.LOW_LIMIT < 47
        and (a <= 46 and lift_a() or b <= 46 and lift_b())
    )


# AST mutation names are resolved through the actual rules module.
MODULUS = P
arithmetic = rules.arithmetic


@pytest.mark.parametrize(
    "a,b,expected",
    [(0, 0, False), (23, 23, False), (47, 1, False), (P - 1, 1, False), (P - 1, 48, False), (P - 2, LOW + 48, True)],
)
def test_residue_only_addition_regions_do_not_query_lifts(a: int, b: int, expected: bool) -> None:
    assert rules.lazy_addition_defect(a, b, unexpected_callback, unexpected_callback) == expected


def test_small_sum_and_short_circuits_the_right_lift() -> None:
    assert not rules.lazy_addition_defect(24, 24, lambda: False, unexpected_callback)
    assert rules.lazy_addition_defect(24, 24, lambda: True, lambda: True)
    assert not rules.lazy_addition_defect(24, 24, lambda: True, lambda: False)


@pytest.mark.parametrize("left_is_small", [False, True])
def test_low_word_region_queries_only_the_ambiguous_operand(left_is_small: bool) -> None:
    a, b = (1, LOW - 1) if left_is_small else (LOW - 1, 1)
    for lifted in (False, True):
        first = (lambda: lifted) if left_is_small else unexpected_callback
        last = unexpected_callback if left_is_small else (lambda: lifted)
        assert rules.lazy_addition_defect(a, b, first, last) == lifted


@pytest.mark.parametrize("a,b", [(1, 0), (1, 1), (0, 47), (46, 47)])
def test_impossible_subtraction_region_queries_neither_lift(a: int, b: int) -> None:
    assert not rules.lazy_subtraction_defect(a, b, unexpected_callback, unexpected_callback)


def test_subtraction_true_left_lift_short_circuits_right() -> None:
    assert not rules.lazy_subtraction_defect(1, 2, lambda: True, unexpected_callback)
    assert rules.lazy_subtraction_defect(1, 2, lambda: False, lambda: True)
    assert not rules.lazy_subtraction_defect(1, 2, lambda: False, lambda: False)


def test_all_small_legal_lifts_and_large_boundaries_match_the_independent_rules() -> None:
    inputs = [rules.Representative(r, t) for r in range(47) for t in (False, True)]
    inputs.extend(rules.Representative(r) for r in (47, 48, LOW - 47, LOW - 1, LOW, LOW + 48, P - 2, P - 1))
    for a in inputs:
        for b in inputs:
            add = rules.lazy_addition_defect(a.residue, b.residue, lambda: a.lifted, lambda: b.lifted)
            sub = rules.lazy_subtraction_defect(a.residue, b.residue, lambda: a.lifted, lambda: b.lifted)
            assert add == rules.addition_defect(a.residue + b.residue, int(a.lifted) + int(b.lifted))
            assert sub == rules.subtraction_defect(a.residue, b.residue, a.lifted, b.lifted)


def two_squares(operation: str) -> Program:
    instructions = (
        Instruction(0, 0, 2, "square", (Operand("input", 0),), 0),
        Instruction(1, 1, 3, "square", (Operand("input", 1),), 0),
        Instruction(2, 2, 4, operation, (Operand("value", 0), Operand("value", 1)), 0),
    )
    return Program(0, 3, 5, 0, instructions, ((4, Operand("value", 2)),))


def packed_oracle(source: Program, state: dict[int, int]) -> dict[int, int]:
    context = bytearray(source.context_slots * 24)
    for slot, value in state.items():
        context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
    exact.execute_program(source, context)
    return {slot: exact.decode(context[slot * 24 : (slot + 1) * 24]) for slot, _ in source.outputs}


def test_false_addition_guard_skips_the_right_square_history() -> None:
    source = two_squares("add")
    plan = compiler.compile_plan(source)
    state = {0: 5, 1: P + 5}
    result = compiler.evaluate(plan, state)
    baseline = compiler.evaluate(plan, state, lazy_guards=False)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: 50}
    assert result.defects == baseline.defects == ()
    assert (result.tag_rules, baseline.tag_rules) == (1, 2)
    assert result.guard_lift_queries == 1 and result.potential_guards == 1


def test_false_subtraction_guard_skips_the_right_square_history() -> None:
    source = two_squares("subtract")
    plan = compiler.compile_plan(source)
    state = {0: P + 1, 1: P + 2}
    result = compiler.evaluate(plan, state)
    baseline = compiler.evaluate(plan, state, lazy_guards=False)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: P - 3}
    assert result.defects == baseline.defects == ()
    assert (result.tag_rules, baseline.tag_rules) == (1, 2)
    assert result.guard_lift_queries == 1 and result.potential_guards == 1


def test_true_guard_retains_its_exact_correction_and_event() -> None:
    source = two_squares("add")
    plan = compiler.compile_plan(source)
    state = {0: P + 5, 1: P + 5}
    result = compiler.evaluate(plan, state)
    baseline = compiler.evaluate(plan, state, lazy_guards=False)
    assert result.outputs == baseline.outputs == packed_oracle(source, state)
    assert result.defects == baseline.defects and len(result.defects) == 1
    assert result.defects[0].correction == rules.arithmetic.ADD_DEFECT
    with patch.object(rules, "lazy_addition_defect", without_two_lifts):
        wrong = compiler.evaluate(plan, state)
    assert wrong.outputs != result.outputs and wrong.defects == ()


def test_false_positive_guard_is_rejected_by_the_independent_correction_oracle() -> None:
    source = two_squares("add")
    plan = compiler.compile_plan(source)
    with patch.object(rules, "lazy_addition_defect", return_value=True):
        with pytest.raises(ValueError, match="disagrees"):
            compiler.evaluate(plan, {0: 5, 1: 5})


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_recovered_stage_guard_pruning_preserves_outputs_and_events(cap: int) -> None:
    source = recover()[1].choices[0]
    plan = compiler.compile_plan(source, cap)
    state = {slot: P + 1 for slot in plan.input_slots}
    result = compiler.evaluate(plan, state, 1, 0)
    baseline = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
    expected, events = evaluate_stage(1, state, 0)
    assert result.outputs == baseline.outputs == expected == packed_oracle(source, state)
    assert result.defects == baseline.defects == events
    assert (result.tag_rules, baseline.tag_rules) == (24, 33)
    assert result.guard_lift_queries == 8 and result.settled_potential_guards == 2


def test_actual_guard_ast_source_obligations_and_negative_control() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_lazy_guards import prove

    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 7
    assert sum(len(row["cases"]) for row in report["obligations"]) == 21
    with patch.object(rules, "lazy_addition_defect", without_two_lifts):
        wrong = prove()
    assert not wrong["full_proof"] and wrong["obligations"][0]["cases"][2]["result"] == "sat"


def test_solver_unknown_is_not_a_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_lazy_guards import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]


@pytest.mark.parametrize("timeout", [0, -1])
def test_nonpositive_solver_timeout_fails_closed(timeout: int) -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_lazy_guards import prove

    with pytest.raises(ValueError, match="positive solver timeout"):
        prove(timeout)
