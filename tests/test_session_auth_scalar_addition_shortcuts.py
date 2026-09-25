"""Exact lazy addition tags: proof, callback demand and source controls."""

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
    raise AssertionError("unnecessary addition lift dependency")


def eager_addition(s: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Original nonzero eager tag rule, retaining its zero-output shortcut."""
    if s == P:
        return True
    if s == 0:
        return lift_a() or lift_b()
    k = int(lift_a()) + int(lift_b())
    return rules.addition_tag(s, k, rules.addition_defect(s, k))


def without_wrap(s: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return s <= 46 and (lift_a() or lift_b())


@pytest.mark.parametrize(
    "s,expected",
    [(47, False), (92, False), (P - 1, False), (P, True), (P + 1, True), (P + 46, True), (P + 47, False), (2 * P - 2, False)],
)
def test_settled_sum_does_not_query_either_lift(s: int, expected: bool) -> None:
    assert rules.addition_lift(s, unexpected_callback, unexpected_callback) == expected


@pytest.mark.parametrize("s", [0, 1, 2, 46])
def test_true_left_lift_short_circuits_the_right(s: int) -> None:
    assert rules.addition_lift(s, lambda: True, unexpected_callback)


@pytest.mark.parametrize("right_lift", [False, True])
def test_false_left_lift_requires_the_right_bit_in_order(right_lift: bool) -> None:
    queries = []

    def first() -> bool:
        queries.append("left")
        return False

    def last() -> bool:
        queries.append("right")
        return right_lift

    assert rules.addition_lift(2, first, last) == right_lift
    assert queries == ["left", "right"]


def test_every_small_lift_pair_and_large_boundaries_match_the_integer_oracle() -> None:
    representatives = [rules.Representative(r, t) for r in range(47) for t in (False, True)]
    representatives.extend(
        rules.Representative(r) for r in (47, 48, (1 << 128) - 47, (1 << 128) - 1, (1 << 128) + 48, P - 47, P - 2, P - 1)
    )
    defects = 0
    for a in representatives:
        for b in representatives:
            s, k = a.residue + b.residue, int(a.lifted) + int(b.lifted)
            defect = rules.addition_defect(s, k)
            defects += defect
            tag = rules.addition_lift(s, lambda: a.lifted, lambda: b.lifted)
            assert tag == rules.addition_tag(s, k, defect) == (exact.add(a.integer(), b.integer()) >= P)
            if defect:
                assert not tag
    assert defects > 0


def toy(two_squares: bool = False) -> Program:
    instructions = [Instruction(0, 0, 2, "square", (Operand("input", 0),), 0)]
    last = Operand("input", 1)
    if two_squares:
        instructions.append(Instruction(1, 1, 3, "square", (Operand("input", 1),), 0))
        last = Operand("value", 1)
    value = len(instructions)
    instructions.append(Instruction(value, value, 4, "add", (Operand("value", 0), last), 0))
    return Program(0, len(instructions), 5, 0, tuple(instructions), ((4, Operand("value", value)),))


def packed_oracle(source: Program, state: dict[int, int]) -> dict[int, int]:
    context = bytearray(source.context_slots * 24)
    for slot, value in state.items():
        context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
    exact.execute_program(source, context)
    return {slot: exact.decode(context[slot * 24 : (slot + 1) * 24]) for slot, _ in source.outputs}


@pytest.mark.parametrize("right_lifted", [False, True])
def test_small_sum_can_skip_the_right_square_history(right_lifted: bool) -> None:
    source = toy(two_squares=True)
    plan = compiler.compile_plan(source)
    state = {0: P + 1, 1: 1 + P * right_lifted}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "addition_lift", eager_addition):
        baseline = compiler.evaluate(plan, state)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: P + 2}
    assert (result.tag_rules, baseline.tag_rules) == (2, 3)
    assert (result.addition_lift_queries, baseline.addition_lift_queries) == (1, 2)


@pytest.mark.parametrize("left", [2, P + 2])
def test_wrap_interval_skips_the_left_square_history(left: int) -> None:
    source = toy()
    plan = compiler.compile_plan(source)
    state = {0: left, 1: P - 3}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "addition_lift", eager_addition):
        baseline = compiler.evaluate(plan, state)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: P + 1}
    assert (result.tag_rules, baseline.tag_rules) == (1, 2)
    assert result.addition_rules == 1 and result.addition_lift_queries == 0
    with patch.object(rules, "addition_lift", without_wrap):
        wrong = compiler.evaluate(plan, state)
    assert wrong.outputs == {4: 1}


@pytest.mark.parametrize("first,last", [(0, 0), (0, P), (P, 0), (P, P)])
def test_zero_outputs_preserve_the_original_lazy_positivity_rule(first: int, last: int) -> None:
    source = toy(two_squares=True)
    plan = compiler.compile_plan(source)
    state = {0: first, 1: last}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "addition_lift", eager_addition):
        baseline = compiler.evaluate(plan, state)
    assert result.outputs == baseline.outputs == packed_oracle(source, state) == {4: P if first or last else 0}
    assert result.tag_rules == baseline.tag_rules
    assert result.addition_lift_queries == baseline.addition_lift_queries


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_recovered_stage_one_prunes_tags_at_each_formula_bound(cap: int) -> None:
    # Legal synthetic stage boundary, not asserted reachable from full inputs.
    # Both runs retain identical multiplication/subtraction behavior; the
    # baseline preserves the old addition zero-output shortcut as well.
    source = recover()[1].choices[0]
    plan = compiler.compile_plan(source, cap)
    state = {slot: 1 for slot in plan.input_slots}
    result = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
    with patch.object(rules, "addition_lift", eager_addition):
        baseline = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
    expected, events = evaluate_stage(1, state, 0)
    assert result.outputs == baseline.outputs == expected == packed_oracle(source, state)
    assert result.defects == baseline.defects == events
    assert (result.tag_rules, baseline.tag_rules) == (42, 47)
    assert (result.addition_lift_queries, baseline.addition_lift_queries) == (5, 16)


def test_actual_lazy_rule_ast_and_all_twenty_one_source_cases() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_addition_shortcuts import prove
    from tools.prove_scalar_predicate_guards import compile_guard

    context = z3.Context()
    for s in (0, 46, 47, P - 1, P, P + 46, P + 47):
        for ta in (False, True):
            for tb in (False, True):
                expressions = {
                    "s": z3.IntVal(s, ctx=context),
                    "lift_a": z3.BoolVal(ta, ctx=context),
                    "lift_b": z3.BoolVal(tb, ctx=context),
                }
                predicate = compile_guard(z3, "addition_lift", expressions, module=rules)
                assert z3.is_true(z3.simplify(predicate)) == rules.addition_lift(s, lambda: ta, lambda: tb)
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 7
    assert sum(len(row["cases"]) for row in report["obligations"]) == 21
    with patch.object(rules, "addition_lift", without_wrap):
        wrong = prove()
    assert not wrong["full_proof"] and wrong["obligations"][0]["cases"][0]["result"] == "sat"


def test_solver_unknown_is_not_a_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_addition_shortcuts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        report = prove()
    assert not report["full_proof"] and all(not row["proved"] for row in report["obligations"])


@pytest.mark.parametrize("timeout", [0, -1])
def test_nonpositive_solver_timeouts_fail_closed(timeout: int) -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_addition_shortcuts import prove

    with pytest.raises(ValueError, match="positive solver timeout"):
        prove(timeout)
