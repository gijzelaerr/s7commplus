"""Bounded carry/tag formula plans: all-stage, structural, and byte controls."""

import random
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import predict_scalar_defects as predictor
from tools import scalar_representative_program as representative_program
from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as plan_model
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as arithmetic
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import finalize, model as reference, tail_program
from tools.transform7_setup_integer import model as setup


def base_point() -> tuple[int, int]:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    return x, y


def primitive(operation: str) -> Program:
    operands = (Operand("input", 0),) if operation == "square" else (Operand("input", 0), Operand("input", 1))
    instruction = Instruction(0, 0, 2, operation, operands, 0)
    return Program(0, 1, 3, 0, (instruction,), ((2, Operand("value", 0)),))


def test_all_320_branches_with_boundaries_random_inputs_and_exact_carry_events() -> None:
    rng = random.Random(320256)
    pool = (0, 1, 46, 47, arithmetic.P, arithmetic.P + 46, exact.MASK)
    excluded = 0
    guards = 0
    for stage in stages():
        for bit, program in enumerate(stage.choices):
            plan = plan_model.compile_plan(program)
            plan_model.validate_order(plan)
            excluded += plan.excluded_guards
            guards += len(plan.guards)
            states = [{s: pool[(k + j) % len(pool)] for j, s in enumerate(stage.inputs)} for k in range(len(pool))]
            states.append({s: rng.getrandbits(160) for s in stage.inputs})
            for state in states:
                result = plan_model.evaluate(plan, state, stage.index, bit)
                actual, events = evaluate_stage(stage.index, state, bit)
                assert result.outputs == actual and result.defects == events, (stage.index, bit, state)
                assert all(len(poly) <= plan.max_terms for poly in (*plan.fields.values(), *plan.anchors))
    assert (guards, excluded) == (20129, 1584)


@pytest.mark.parametrize("operation", ["add", "subtract", "multiply", "square"])
def test_primitive_plans_cover_uint160_boundaries(operation: str) -> None:
    program = primitive(operation)
    p = arithmetic.P
    pool = (0, 1, 46, 47, (1 << 128) + 48, p - 2, p - 1, p, p + 1, exact.MASK)
    plan = plan_model.compile_plan(program)
    for a in pool:
        for b in pool:
            state = {0: a} if operation == "square" else {0: a, 1: b}
            result = plan_model.evaluate(plan, state)
            expected = representative_program.execute(program, state)
            assert result.outputs == expected.outputs
            assert tuple(zip(result.defect_values, (e.correction for e in result.defects))) == expected.corrections


@pytest.mark.parametrize("n", [0, 1, 2, 16, (1 << 79) - 1, (1 << 159) + 123])
def test_full_72_bytes_and_all_boundaries_match_separate_evaluator(n: int) -> None:
    x, y = base_point()
    selector = n ^ scalar_xor_mask()
    output, rows = plan_model.full_output(x, y, 0, selector)
    expected, expected_rows = representative_program.full_output(x, y, 0, selector)
    assert output == expected
    assert [row.outputs for row in rows] == [row.outputs for row in expected_rows]
    assert [tuple(zip(row.defect_values, (e.correction for e in row.defects))) for row in rows] == [
        row.corrections for row in expected_rows
    ]
    if n == 0:
        assert [(e.stage, e.tape_index) for row in rows for e in row.defects] == [(79, 36796), (79, 36808), (80, 1092)]
        assert sum(row.potential_guards for row in rows) == 4
        assert sum(row.guards for row in rows) < sum(row.instructions for row in expected_rows)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_polynomial_anchor_limits_do_not_change_complete_results(cap: int) -> None:
    x, y = base_point()
    selector = scalar_xor_mask()
    output, rows = plan_model.full_output(x, y, 0, selector, cap)
    expected, _ = representative_program.full_output(x, y, 0, selector)
    assert output == expected and sum(len(row.defects) for row in rows) == 3
    # Both problematic groups are handled by bounded formulas, not an old
    # arithmetic fallback. Their unrestricted error expansion exceeds4096.
    for program in (stages()[0].choices[0], tail_program()):
        plan = plan_model.compile_plan(program, cap)
        assert plan.anchors
        plan_model.validate_order(plan)
        assert all(len(poly) <= cap for poly in (*plan.fields.values(), *plan.anchors))


def test_arbitrary_complete_inputs_and_on_curve_point_changing_carries() -> None:
    rng = random.Random(72256)
    cases = [(0, 0, 0, 0), (exact.MASK,) * 4, (arithmetic.P, arithmetic.P, arithmetic.P, exact.MASK)]
    cases.append(((1 << 128) + 48, 917984300236617229462155822449362250189314875415, 0, 0))
    cases.extend(tuple(rng.getrandbits(160) for _ in range(4)) for _ in range(3))
    for x, y, prng1, selector in cases:
        output, rows = plan_model.full_output(x, y, prng1, selector)
        expected = reference(
            prng1.to_bytes(20, "little"), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little")
        )
        assert output == expected.destination
        assert rows[159].outputs == dict(zip((5, 87), expected.tail_inputs))
        if x == (1 << 128) + 48:
            destination = bytearray(72)
            transform7.execute(destination, bytearray(20), bytearray(20), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
            assert output == bytes(destination) and len(rows[1].defects) == 2


def test_nonlinear_corrections_and_cached_plans_need_no_repairs() -> None:
    state = dict(zip(stages()[0].inputs, setup((1 << 128) + 48, 0, 0).slots))
    state, _ = evaluate_stage(0, state, 0)
    plan = plan_model.compile_plan(stages()[1].choices[0])
    before = deepcopy(plan)
    result = plan_model.evaluate(plan, state, 1, 0)
    expected, events = evaluate_stage(1, state, 0)
    assert result.outputs == expected and result.defects == events and len(events) == 2
    assert plan == before
    assert plan_model.evaluate(plan, state, 1, 0) == result
    # Error variables have genuine powers/interactions in the compiled
    # source formulas; this is not an additive-only defect approximation.
    error_ids = {i for i, b in enumerate(plan.bindings) if b.kind == "correction"}
    assert any(
        sum(exponent for v, exponent in monomial if v in error_ids) > 1 for poly in plan.fields.values() for monomial in poly
    )


def test_runtime_never_replays_numeric_instructions_or_repairs_polynomials() -> None:
    x, y = base_point()
    selector = scalar_xor_mask()
    selected = [(stage.index, selector >> (159 - stage.index) & 1, stage) for stage in stages()]
    plans = [plan_model.compile_plan(stage.choices[bit]) for _, bit, stage in selected]
    fixed = plan_model.compile_plan(tail_program())
    expected, _ = representative_program.full_output(x, y, 0, selector)
    state = dict(zip(stages()[0].inputs, setup(x, y, 0).slots))
    with (
        patch.object(exact, "add", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "subtract", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "multiply", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "execute_program", side_effect=AssertionError("old SSA executor")),
        patch.object(arithmetic, "add", side_effect=AssertionError("lifted oracle")),
        patch.object(arithmetic, "subtract", side_effect=AssertionError("lifted oracle")),
        patch.object(arithmetic, "multiply", side_effect=AssertionError("lifted oracle")),
        patch.object(predictor, "predict_program", side_effect=AssertionError("repairing predictor")),
        patch.object(representative_program, "execute", side_effect=AssertionError("residue SSA executor")),
        patch.object(plan_model, "operation", side_effect=AssertionError("compile-time equations")),
        patch.object(plan_model, "combine", side_effect=AssertionError("polynomial repair")),
        patch.object(plan_model, "product", side_effect=AssertionError("polynomial repair")),
        patch.object(plan_model, "compile_plan", side_effect=AssertionError("runtime compilation")),
    ):
        for plan, (index, bit, _) in zip(plans, selected):
            state = plan_model.evaluate(plan, state, index, bit).outputs
        assert finalize(plan_model.evaluate(fixed, state).outputs) == expected


def test_frontier_validator_rejects_future_errors_cycles_and_bad_inventory() -> None:
    plan = plan_model.compile_plan(primitive("add"))
    error_id = next(i for i, binding in enumerate(plan.bindings) if binding.kind == "correction")
    guard = replace(plan.guards[0], before=plan_model.variable(error_id))
    invalid = replace(plan, guards=(guard,))
    with pytest.raises(ValueError, match="unresolved correction"):
        plan_model.validate_order(invalid)
    with pytest.raises(ValueError, match="unresolved correction"):
        plan_model.evaluate(invalid, {0: 1, 1: 2})
    with pytest.raises(ValueError, match="guard inventory"):
        plan_model.validate_order(replace(plan, guards=()))
    with pytest.raises(ValueError, match="frontier inventory"):
        plan_model.validate_order(replace(plan, frontiers=tuple(99 for _ in plan.frontiers)))
    anchored = plan_model.compile_plan(stages()[0].choices[0], 2)
    anchor_id = next(i for i, binding in enumerate(anchored.bindings) if binding.kind == "anchor")
    polynomials = list(anchored.anchors)
    polynomials[0] = plan_model.variable(anchor_id)
    with pytest.raises(ValueError, match="forward variable"):
        plan_model.validate_order(replace(anchored, anchors=tuple(polynomials)))


def test_carry_and_constant_safety_negative_controls() -> None:
    program = primitive("add")
    state = {0: arithmetic.P - 2, 1: (1 << 128) + 48}
    plan = plan_model.compile_plan(program)
    expected = representative_program.execute(program, state).outputs
    with patch.object(plan_model, "addition_possible", return_value=False):
        assert plan_model.evaluate(plan, state).outputs != expected
    # B-46 is just outside the proved safe interval and can carry.
    instruction = Instruction(0, 0, 2, "add", (Operand("input", 0), Operand("constant", 0)), 0)
    program = Program(0, 1, 3, 1, (instruction,), ((2, Operand("value", 0)),))
    plan_model.compile_plan.cache_clear()
    with patch.object(plan_model, "constant", return_value=arithmetic.LOW_LIMIT - 46):
        plan = plan_model.compile_plan(program)
        assert len(plan.guards) == 1
        result = plan_model.evaluate(plan, {0: exact.LIMIT - 1})
        assert len(result.defects) == 1
        with patch.object(rules, "addition_constant_safe", return_value=True):
            plan_model.compile_plan.cache_clear()
            incorrect = plan_model.compile_plan(program)
            assert plan_model.evaluate(incorrect, {0: exact.LIMIT - 1}).outputs != result.outputs
    plan_model.compile_plan.cache_clear()


@pytest.mark.parametrize("cap", [0, 1, True])
def test_invalid_term_bounds_fail_closed(cap: int) -> None:
    with pytest.raises(ValueError):
        plan_model.compile_plan(primitive("add"), cap)


def test_invalid_domains_and_unsupported_operations_fail_closed() -> None:
    plan = plan_model.compile_plan(primitive("add"))
    for state in ({0: 1}, {0: -1, 1: 0}, {0: exact.LIMIT, 1: 0}):
        with pytest.raises(ValueError):
            plan_model.evaluate(plan, state)
    with pytest.raises(ValueError):
        plan_model.compile_plan(primitive("unknown"))
    with pytest.raises(ValueError):
        plan_model.evaluate(plan, {0: 1, 1: 2}, bit=2)


def test_description_exposes_output_formulas_and_source_carry_provenance() -> None:
    plan = plan_model.compile_plan(stages()[80].choices[1])
    description = plan_model.describe(plan)
    assert description["source_instructions"] == len(plan.program.instructions)
    assert description["excluded_constant_carry_sites"] == plan.excluded_guards
    assert set(description["outputs"]) == {str(s) for s, _ in plan.program.outputs}
    assert [row["tape_index"] for row in description["carry_sites"]] == [g.instruction.tape_index for g in plan.guards]
    for output in description["outputs"].values():
        assert output["field_formula"].endswith("% p")
        assert set(output["carry_dependencies"]) <= {g.instruction.value for g in plan.guards}
