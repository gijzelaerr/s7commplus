"""Exact lazy subtraction tags: proof, callback demand and source controls."""

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


def unexpected_callback() -> bool:
    raise AssertionError("unnecessary subtraction lift dependency")


def eager_subtraction(a: int, b: int, defective: bool, first: Callable[[], bool], last: Callable[[], bool]) -> bool:
    return rules.subtraction_tag(a, b, first(), last())


def eager_addition(s: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    # Preserve the original zero-output positivity shortcut.
    if s == P:
        return True
    if s == 0:
        return lift_a() or lift_b()
    k = int(lift_a()) + int(lift_b())
    return rules.addition_tag(s, k, rules.addition_defect(s, k))


def without_defect(a: int, b: int, defective: bool, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return b <= a <= 46 and lift_a() and not lift_b()


@pytest.mark.parametrize(
    "a,b,defect,expected",
    [
        (1, P - 1, False, False),
        (P - 1, 1, False, False),
        (47, 47, False, False),
        (0, 1, True, True),
        (0, 46, True, True),
        (1, 2, False, False),
    ],
)
def test_settled_subtraction_does_not_query_either_lift(a: int, b: int, defect: bool, expected: bool) -> None:
    assert rules.subtraction_lift(a, b, defect, unexpected_callback, unexpected_callback) == expected


@pytest.mark.parametrize("a,b", [(4, 2), (1, 1), (0, 0)])
def test_false_left_lift_short_circuits_the_right(a: int, b: int) -> None:
    assert not rules.subtraction_lift(a, b, False, lambda: False, unexpected_callback)


@pytest.mark.parametrize("right_lift", [False, True])
def test_true_left_lift_requires_the_right_bit_in_order(right_lift: bool) -> None:
    queries = []

    def first() -> bool:
        queries.append("left")
        return True

    def last() -> bool:
        queries.append("right")
        return right_lift

    assert rules.subtraction_lift(4, 2, False, first, last) == (not right_lift)
    assert queries == ["left", "right"]


def test_every_small_lift_pair_and_large_boundaries_match_the_integer_oracle() -> None:
    representatives = [rules.Representative(r, t) for r in range(47) for t in (False, True)]
    representatives.extend(rules.Representative(r) for r in (47, 48, (1 << 128) + 48, P - 47, P - 2, P - 1))
    for a in representatives:
        for b in representatives:
            defect = rules.subtraction_defect(a.residue, b.residue, a.lifted, b.lifted)
            tag = rules.subtraction_lift(a.residue, b.residue, defect, lambda: a.lifted, lambda: b.lifted)
            result = exact.subtract(a.integer(), b.integer())
            assert tag == (result >= P)


def toy(two_squares: bool = False, same_operand: bool = False) -> Program:
    instructions = [Instruction(0, 0, 2, "square", (Operand("input", 0),), 0)]
    first = Operand("value", 0)
    last = Operand("input", 1)
    if two_squares:
        instructions.append(Instruction(1, 1, 3, "square", (Operand("input", 1),), 0))
        last = Operand("value", 1)
    if same_operand:
        last = first
    value = len(instructions)
    instructions.append(Instruction(value, value, 4, "subtract", (first, last), 0))
    return Program(0, len(instructions), 5, 0, tuple(instructions), ((4, Operand("value", value)),))


def packed_oracle(source: Program, state: dict[int, int]) -> dict[int, int]:
    context = bytearray(source.context_slots * 24)
    for slot, value in state.items():
        context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
    exact.execute_program(source, context)
    return {slot: exact.decode(context[slot * 24 : (slot + 1) * 24]) for slot, _ in source.outputs}


@pytest.mark.parametrize("lifted_input", [False, True])
def test_large_right_residue_prunes_an_earlier_square_tag(lifted_input: bool) -> None:
    source = toy()
    plan = compiler.compile_plan(source)
    state = {0: 1 + P * lifted_input, 1: P - 1}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "subtraction_lift", eager_subtraction):
        baseline = compiler.evaluate(plan, state)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: 2}
    assert result.tag_rules == 1 < baseline.tag_rules == 2
    assert result.subtraction_rules == 1 and result.subtraction_lift_queries == 0


@pytest.mark.parametrize("right_lifted", [False, True])
def test_zero_output_can_skip_the_right_square_history(right_lifted: bool) -> None:
    source = toy(two_squares=True)
    plan = compiler.compile_plan(source)
    state = {0: 1, 1: 1 + P * right_lifted}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "subtraction_lift", eager_subtraction):
        baseline = compiler.evaluate(plan, state)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: 0}
    assert (result.tag_rules, baseline.tag_rules) == (2, 3)
    assert (result.subtraction_lift_queries, baseline.subtraction_lift_queries) == (1, 2)


def test_equal_residues_from_different_operands_do_not_settle_the_lift() -> None:
    source = toy(two_squares=True)
    plan = compiler.compile_plan(source)
    for right in (1, P + 1):
        state = {0: P + 1, 1: right}
        result = compiler.evaluate(plan, state)
        assert result.outputs == packed_oracle(source, state) == {4: P if right == 1 else 0}
        assert result.subtraction_lift_queries == 2


def test_identical_source_operand_skips_both_lift_histories() -> None:
    source = toy(same_operand=True)
    plan = compiler.compile_plan(source)
    for first in (1, P + 1):
        with patch.object(rules, "subtraction_lift", side_effect=AssertionError("identical operand")):
            result = compiler.evaluate(plan, {0: first})
        assert result.outputs == packed_oracle(source, {0: first}) == {4: 0}
        assert result.tag_rules == 1 and result.nonzero_product_rules == result.subtraction_lift_queries == 0


def test_known_correction_preserves_the_exceptional_small_lift() -> None:
    instruction = Instruction(0, 0, 2, "subtract", (Operand("input", 0), Operand("input", 1)), 0)
    source = Program(0, 1, 3, 0, (instruction,), ((2, Operand("value", 0)),))
    plan = compiler.compile_plan(source)
    result = compiler.evaluate(plan, {0: 0, 1: P + 46})
    assert result.outputs == packed_oracle(source, {0: 0, 1: P + 46}) == {2: P + 1}
    assert result.defects[0].correction == 47 and result.subtraction_lift_queries == 0
    with patch.object(rules, "subtraction_lift", without_defect):
        wrong = compiler.evaluate(plan, {0: 0, 1: P + 46})
    assert wrong.outputs == {2: 1}


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_recovered_stage_one_prunes_tags_at_each_formula_bound(cap: int) -> None:
    # Legal synthetic stage boundary; complete-input reachability is not
    # asserted. Hold multiplication fixed and addition demand at its old baseline.
    source = recover()[1].choices[0]
    plan = compiler.compile_plan(source, cap)
    state = {slot: 1 for slot in plan.input_slots}
    with patch.object(rules, "addition_lift", eager_addition):
        result = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
        with patch.object(rules, "subtraction_lift", eager_subtraction):
            baseline = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
    expected, events = evaluate_stage(1, state, 0)
    assert result.outputs == baseline.outputs == expected == packed_oracle(source, state)
    assert result.defects == baseline.defects == events
    assert (result.tag_rules, baseline.tag_rules) == (47, 49)
    assert (result.subtraction_lift_queries, baseline.subtraction_lift_queries) == (6, 12)


def test_actual_lazy_rule_ast_and_all_seven_source_obligations() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import compile_guard
    from tools.prove_scalar_subtraction_shortcuts import prove

    context = z3.Context()
    for a, b in ((0, 0), (0, 46), (46, 0), (46, 46), (47, 46)):
        for ta in (False, True):
            for tb in (False, True):
                defect = rules.subtraction_defect(a, b, ta, tb)
                expressions = {
                    "a": z3.IntVal(a, ctx=context),
                    "b": z3.IntVal(b, ctx=context),
                    "defective": z3.BoolVal(defect, ctx=context),
                    "lift_a": z3.BoolVal(ta, ctx=context),
                    "lift_b": z3.BoolVal(tb, ctx=context),
                }
                predicate = compile_guard(z3, "subtraction_lift", expressions, module=rules)
                assert z3.is_true(z3.simplify(predicate)) == rules.subtraction_lift(a, b, defect, lambda: ta, lambda: tb)
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 7
    with patch.object(rules, "subtraction_lift", without_defect):
        wrong = prove()
    assert not wrong["full_proof"] and wrong["obligations"][0]["result"] == "sat"


def test_solver_unknown_is_not_a_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_subtraction_shortcuts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        report = prove()
    assert not report["full_proof"] and all(not row["proved"] for row in report["obligations"])


@pytest.mark.parametrize("timeout", [0, -1])
def test_nonpositive_solver_timeouts_fail_closed(timeout: int) -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_subtraction_shortcuts import prove

    with pytest.raises(ValueError, match="positive solver timeout"):
        prove(timeout)
