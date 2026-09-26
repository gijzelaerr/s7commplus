"""Nonzero multiplication lift proof and actual lazy-dependency controls."""

from collections.abc import Callable
from types import ModuleType
from unittest.mock import patch

import pytest

from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage


def eager_lift(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    """Value-equivalent baseline that always requests both operand lifts."""
    ta, tb = lift_a(), lift_b()
    return (a != 0 or ta) and (b != 0 or tb) and (ta or tb or a * b >= rules.MODULUS)


def eager_subtraction(a: int, b: int, defective: bool, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return rules.subtraction_tag(a, b, lift_a(), lift_b())


def eager_addition(s: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    # Preserve the original zero-output positivity shortcut.
    if s == rules.MODULUS:
        return True
    if s == 0:
        return lift_a() or lift_b()
    k = int(lift_a()) + int(lift_b())
    return rules.addition_tag(s, k, rules.addition_defect(s, k))


def threshold_only(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return a * b >= MODULUS


MODULUS = rules.MODULUS


def unexpected_callback() -> bool:
    raise AssertionError("unnecessary lift dependency")


def square_then_multiply() -> Program:
    instructions = (
        Instruction(0, 0, 2, "square", (Operand("input", 0),), 0),
        Instruction(1, 1, 3, "multiply", (Operand("value", 0), Operand("input", 1)), 0),
    )
    return Program(0, 2, 4, 0, instructions, ((3, Operand("value", 1)),))


def toy_oracle(state: dict[int, int]) -> dict[int, int]:
    return {3: exact.multiply(exact.multiply(state[0], state[0]), state[1])}


@pytest.mark.parametrize("small_first", [True, False])
def test_crossing_p_settles_the_lift_without_either_callback(small_first: bool) -> None:
    a, b = 2, (MODULUS + 1) // 2
    if not small_first:
        a, b = b, a
    assert a * b == MODULUS + 1
    assert rules.nonzero_product_lift(a, b, unexpected_callback, unexpected_callback)


@pytest.mark.parametrize("lifted", [False, True])
def test_below_threshold_retains_the_ambiguous_operand_lift(lifted: bool) -> None:
    queries = []

    def first() -> bool:
        queries.append("first")
        return lifted

    def second() -> bool:
        queries.append("second")
        return False

    assert rules.nonzero_product_lift(1, 2, first, second) == lifted
    assert queries == (["first"] if lifted else ["first", "second"])


@pytest.mark.parametrize("small_first", [True, False])
def test_unique_operand_never_requests_a_lift(small_first: bool) -> None:
    # 1*47 has residue47, outside the caller's small-output domain, but
    # still checks the helper's stronger positive-input threshold rule.
    def small() -> bool:
        return False

    a, b = (1, 47) if small_first else (47, 1)
    callbacks = (small, unexpected_callback) if small_first else (unexpected_callback, small)
    assert not rules.nonzero_product_lift(a, b, *callbacks)


def test_all_small_lifts_and_large_threshold_boundaries_match_the_fold_oracle() -> None:
    small = [rules.Representative(r, t) for r in range(1, 47) for t in (False, True)]
    large = [rules.Representative(r) for r in (47, (MODULUS + 1) // 2, (MODULUS + 3) // 4, MODULUS - 2, MODULUS - 1)]
    for a in small + large:
        for b in small + large:
            residue = a.residue * b.residue % MODULUS
            if 0 < residue <= 46:
                lifted = rules.nonzero_product_lift(a.residue, b.residue, lambda: a.lifted, lambda: b.lifted)
                assert residue + MODULUS * lifted == exact.multiply(a.integer(), b.integer())


@pytest.mark.parametrize("lifted_input", [False, True])
def test_stage_shortcut_prunes_a_real_earlier_tag_dependency(lifted_input: bool) -> None:
    source = square_then_multiply()
    plan = compiler.compile_plan(source)
    state = {0: 2 + MODULUS * lifted_input, 1: (MODULUS + 3) // 4}
    result = compiler.evaluate(plan, state)
    with patch.object(rules, "nonzero_product_lift", eager_lift):
        eager = compiler.evaluate(plan, state)
    assert result.outputs == eager.outputs == toy_oracle(state)
    assert result.outputs[3] == MODULUS + 3
    assert result.tag_rules == 1 < eager.tag_rules == 2
    assert result.nonzero_product_rules == 1 and result.product_lift_queries == 0
    assert eager.product_lift_queries >= 2


def test_below_threshold_stage_outputs_still_depend_on_earlier_lifts() -> None:
    plan = compiler.compile_plan(square_then_multiply())
    canonical = compiler.evaluate(plan, {0: 1, 1: 2})
    lifted = compiler.evaluate(plan, {0: MODULUS + 1, 1: 2})
    assert canonical.outputs[3] == 2 and lifted.outputs[3] == MODULUS + 2
    assert canonical.product_lift_queries > 0 and lifted.product_lift_queries > 0


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_recovered_stage_one_prunes_sixteen_tag_rules_without_changing_outputs(cap: int) -> None:
    # Synthetic legal stage inputs; full Transform7 reachability is not
    # asserted. This exercises the real recovered source, not just a toy.
    source = recover()[1].choices[0]
    plan = compiler.compile_plan(source, cap)
    state = {slot: MODULUS + 1 for slot in plan.input_slots}
    # Isolate the product cut: keep addition/subtraction at their old eager
    # baseline, even as other lift rules gain independent shortcuts.
    with patch.object(rules, "subtraction_lift", eager_subtraction), patch.object(rules, "addition_lift", eager_addition):
        result = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
        with patch.object(rules, "nonzero_product_lift", eager_lift):
            baseline = compiler.evaluate(plan, state, 1, 0, lazy_guards=False)
    expected, events = evaluate_stage(1, state, 0)
    context = bytearray(source.context_slots * 24)
    for slot, value in state.items():
        context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
    exact.execute_program(source, context)
    packed = {slot: exact.decode(context[slot * 24 : (slot + 1) * 24]) for slot, _ in source.outputs}
    assert result.outputs == baseline.outputs == expected == packed
    assert result.defects == baseline.defects == events
    assert (result.tag_rules, baseline.tag_rules) == (33, 49)
    assert (result.product_lift_queries, baseline.product_lift_queries) == (24, 54)


def test_zero_outputs_keep_the_original_positivity_rule() -> None:
    # The nonzero shortcut would wrongly lift 0*p if applied at zero.
    assert rules.nonzero_product_lift(0, 0, lambda: True, lambda: False)
    assert exact.multiply(MODULUS, 0) == 0
    plan = compiler.compile_plan(square_then_multiply())
    for first, last in ((MODULUS, 0), (0, MODULUS), (MODULUS, MODULUS)):
        state = {0: first, 1: last}
        with patch.object(rules, "nonzero_product_lift", side_effect=AssertionError("zero shortcut")):
            result = compiler.evaluate(plan, state)
        assert result.outputs == toy_oracle(state)
        assert result.nonzero_product_rules == result.product_lift_queries == 0


def test_suppressing_the_product_threshold_changes_a_stage_output() -> None:
    plan = compiler.compile_plan(square_then_multiply())
    state = {0: 2, 1: (MODULUS + 3) // 4}
    expected = compiler.evaluate(plan, state)
    with patch.object(rules, "nonzero_product_lift", side_effect=lambda a, b, first, last: first() or last()):
        incorrect = compiler.evaluate(plan, state)
    assert expected.outputs[3] == MODULUS + 3 and incorrect.outputs[3] == 3


def test_actual_callback_rule_ast_and_all_seven_solver_obligations() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import compile_guard
    from tools.prove_scalar_product_shortcuts import prove

    context = z3.Context()
    for a, b in ((1, 2), (1, 47), (2, (MODULUS + 1) // 2), (MODULUS - 1, MODULUS - 1)):
        for ta in (False, True):
            for tb in (False, True):
                expressions = {
                    "a": z3.IntVal(a, ctx=context),
                    "b": z3.IntVal(b, ctx=context),
                    "lift_a": z3.BoolVal(ta, ctx=context),
                    "lift_b": z3.BoolVal(tb, ctx=context),
                }
                predicate = compile_guard(z3, "nonzero_product_lift", expressions, module=rules)
                assert z3.is_true(z3.simplify(predicate)) == rules.nonzero_product_lift(a, b, lambda: ta, lambda: tb)
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 7
    with patch.object(rules, "nonzero_product_lift", threshold_only):
        broken = prove()
    assert not broken["full_proof"]
    assert broken["obligations"][0]["result"] == "sat"


def callback_with_argument(callback: Callable[[int], bool]) -> bool:
    return callback(1)


def test_guard_compiler_rejects_undeclared_non_boolean_and_argument_callbacks() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import compile_guard

    context = z3.Context()
    inputs = {"a": z3.IntVal(1, ctx=context), "b": z3.IntVal(2, ctx=context), "lift_b": z3.BoolVal(False, ctx=context)}
    for callback in (None, z3.IntVal(0, ctx=context)):
        expressions = dict(inputs)
        if callback is not None:
            expressions["lift_a"] = callback
        with pytest.raises(ValueError, match="unsupported guard expression"):
            compile_guard(z3, "nonzero_product_lift", expressions, module=rules)
    module = ModuleType("argument_callback_control")
    module.callback_with_argument = callback_with_argument
    with pytest.raises(ValueError, match="unsupported guard expression"):
        compile_guard(z3, "callback_with_argument", {"callback": z3.BoolVal(True, ctx=context)}, module=module)


@pytest.mark.parametrize("timeout", [0, -1])
def test_nonpositive_solver_timeouts_fail_closed(timeout: int) -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_product_shortcuts import prove

    with pytest.raises(ValueError, match="positive solver timeout"):
        prove(timeout)


def test_solver_unknown_is_not_a_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_product_shortcuts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        report = prove()
    assert not report["full_proof"] and all(not row["proved"] for row in report["obligations"])
