"""Output-only lazy correction closure; deliberately not a full carry trace."""

import random
from copy import deepcopy
from dataclasses import replace

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

P = compiler.P


def annihilated_product() -> Program:
    instructions = (
        Instruction(0, 0, 3, "add", (Operand("input", 0), Operand("input", 1)), 0),
        Instruction(1, 1, 4, "multiply", (Operand("input", 2), Operand("value", 0)), 0),
    )
    return Program(0, 2, 5, 0, instructions, ((4, Operand("value", 1)),))


@pytest.mark.parametrize("boolean_domain", [False, True])
def test_zero_monomial_omits_an_actual_unobservable_carry(boolean_domain: bool) -> None:
    source = annihilated_product()
    plan = compiler.compile_plan(source, boolean_corrections=boolean_domain)
    state = {0: P - 2, 1: (1 << 128) + 48, 2: 0}
    complete = compiler.evaluate(plan, state)
    needed = compiler.evaluate(plan, state, demand_guards=True)
    assert complete.outputs == needed.outputs == {4: 0}
    assert len(complete.defects) == 1 and needed.defects == ()
    assert complete.guards == 1 and needed.guards == 0 and needed.skipped_guards == 1
    # Multiplication by raw p rather than raw0 has a different zero lift.
    lifted = compiler.evaluate(plan, {**state, 2: P}, demand_guards=True)
    assert lifted.outputs == {4: P}


def test_needed_correction_is_not_skipped() -> None:
    source = annihilated_product()
    plan = compiler.compile_plan(source, boolean_corrections=True)
    state = {0: P - 2, 1: (1 << 128) + 48, 2: 1}
    complete = compiler.evaluate(plan, state)
    needed = compiler.evaluate(plan, state, demand_guards=True)
    assert complete.outputs == needed.outputs == {4: 140}
    assert complete.defects == needed.defects and needed.guards == 1 and needed.skipped_guards == 0


def test_lift_history_remains_needed_when_output_field_is_zero() -> None:
    source = annihilated_product()
    plan = compiler.compile_plan(source, boolean_corrections=True)
    for raw_zero in (0, P):
        complete = compiler.evaluate(plan, {0: P - 1, 1: 1, 2: raw_zero})
        needed = compiler.evaluate(plan, {0: P - 1, 1: 1, 2: raw_zero}, demand_guards=True)
        assert needed.outputs == complete.outputs == {4: raw_zero}


def test_demand_mode_rejects_a_future_correction_read() -> None:
    source = annihilated_product()
    plan = compiler.compile_plan(source)
    broken = deepcopy(plan)
    error = next(v for v, b in enumerate(plan.bindings) if b.kind == "correction")
    guard = broken.guards[0]
    broken = replace(broken, guards=(replace(guard, before={((error, 1),): 1}),))
    with pytest.raises(ValueError, match="unresolved correction"):
        compiler.evaluate(broken, {0: 1, 1: 1, 2: 1}, demand_guards=True)


def test_demand_mode_rejects_an_undefined_correction() -> None:
    source = annihilated_product()
    plan = compiler.compile_plan(source)
    broken = replace(plan, guards=())
    with pytest.raises(ValueError, match="undefined correction"):
        compiler.evaluate(broken, {0: 1, 1: 1, 2: 1}, demand_guards=True)


@pytest.mark.parametrize("boolean_domain", [False, True])
def test_every_scalar_branch_matches_outputs_and_has_only_source_carry_events(boolean_domain: bool) -> None:
    rng = random.Random(6302)
    pool = (0, 1, 46, 47, P, P + 46, exact.MASK)
    skipped = 0
    for stage in recover():
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, boolean_corrections=boolean_domain)
            layouts = [{s: value for s in plan.input_slots} for value in (0, 1, P + 1)]
            layouts.extend({s: pool[(k + j) % len(pool)] for j, s in enumerate(plan.input_slots)} for k in (0, 3))
            layouts.append({s: rng.getrandbits(160) for s in plan.input_slots})
            for state in layouts:
                result = compiler.evaluate(plan, state, stage.index, bit, demand_guards=True)
                expected, events = evaluate_stage(stage.index, state, bit)
                assert result.outputs == expected, (stage.index, bit, state)
                assert all(event in events for event in result.defects)
                assert result.defect_values == tuple(sorted(result.defect_values))
                assert result.guards + result.skipped_guards == len(plan.guards)
                skipped += result.skipped_guards
    assert skipped > 0


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_complete_output_boundaries_and_reference_at_each_bound(cap: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    cases = [(x, y, 0, scalar_xor_mask())]
    cases.append(((1 << 128) + 48, 917984300236617229462155822449362250189314875415, 0, 0))
    for x, y, prng1, scalar in cases:
        expected, complete = compiler.full_output(x, y, prng1, scalar, cap, boolean_corrections=True)
        actual, needed = compiler.full_output(
            x, y, prng1, scalar, cap, boolean_corrections=True, demand_guards=True, verify_algebra=True
        )
        independent = reference(
            prng1.to_bytes(20, "little"), scalar.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little")
        )
        assert actual == expected == independent.destination
        assert [r.outputs for r in needed] == [r.outputs for r in complete]
        assert all(event in complete[i].defects for i, row in enumerate(needed) for event in row.defects)


def test_public_scalar_zero_skips_guards_but_is_explicitly_not_a_full_trace() -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    actual, needed = compiler.full_output(x, y, 0, scalar_xor_mask(), boolean_corrections=True, demand_guards=True)
    expected, complete = compiler.full_output(x, y, 0, scalar_xor_mask())
    assert actual == expected
    assert sum(r.guards for r in needed) == 6302 < sum(r.guards for r in complete) == 10400
    assert sum(r.skipped_guards for r in needed) == 4098
    assert sum(r.tag_rules for r in needed) == 276 < sum(r.tag_rules for r in complete) == 279
    assert sum(len(r.defects) for r in needed) == 2 < sum(len(r.defects) for r in complete) == 3


def test_arbitrary_complete_inputs_keep_exact_bytes() -> None:
    rng = random.Random(4098)
    cases = [(0, 0, 0, 0), (exact.MASK,) * 4, (P, P, P, exact.MASK)]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(4)) for _ in range(2))
    for x, y, prng1, scalar in cases:
        expected, complete = compiler.full_output(x, y, prng1, scalar)
        actual, needed = compiler.full_output(x, y, prng1, scalar, boolean_corrections=True, demand_guards=True)
        assert actual == expected and [r.outputs for r in needed] == [r.outputs for r in complete]


def test_exact_arithmetic_does_not_assume_field_zeros_are_raw_zeros() -> None:
    assert rules.Representative.from_integer(P).integer() == P
    assert rules.Representative.from_integer(0).integer() == 0
