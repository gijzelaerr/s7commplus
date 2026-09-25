"""Explicit two-value correction domains and independent quotient checks."""

import random
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_stage_plan as compiler
from tools import verify_scalar_stage_algebra as checker
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import tail_program

P = compiler.P


def squared_correction(operation: str) -> Program:
    instructions = (
        Instruction(0, 0, 2, operation, (Operand("input", 0), Operand("input", 1)), 0),
        Instruction(1, 1, 3, "square", (Operand("value", 0),), 0),
    )
    return Program(0, 2, 4, 0, instructions, ((3, Operand("value", 1)),))


@pytest.mark.parametrize("operation", ["add", "subtract"])
def test_repeated_error_is_weighted_not_an_unscaled_boolean(operation: str) -> None:
    source = squared_correction(operation)
    plain = compiler.compile_plan(source)
    reduced = compiler.compile_plan(source, boolean_corrections=True)
    weight = compiler.arithmetic_correction(operation) % P
    error = next(v for v, b in enumerate(reduced.bindings) if b.kind == "correction")
    assert ((error, 2),) in plain.fields[1]
    assert ((error, 2),) not in reduced.fields[1]
    assert reduced.fields[1][((error, 1),)] == weight
    cert = checker.verify(reduced, source, boolean_corrections=True)
    assert cert.correction_domains == ((0, weight),)
    broken = deepcopy(reduced)
    broken.fields[1][((error, 1),)] = 1
    with pytest.raises(ValueError, match="field polynomial identity"):
        checker.verify(broken, source, boolean_corrections=True)


def two_error_product() -> Program:
    instructions = (
        Instruction(0, 0, 4, "add", (Operand("input", 0), Operand("input", 1)), 0),
        Instruction(1, 1, 5, "subtract", (Operand("input", 2), Operand("input", 3)), 0),
        Instruction(2, 2, 6, "multiply", (Operand("value", 0), Operand("value", 1)), 0),
    )
    return Program(0, 3, 7, 0, instructions, ((6, Operand("value", 2)),))


def test_cross_error_interactions_are_not_discarded() -> None:
    source = two_error_product()
    plan = compiler.compile_plan(source, boolean_corrections=True)
    errors = tuple(v for v, b in enumerate(plan.bindings) if b.kind == "correction")
    cross = tuple((v, 1) for v in errors)
    assert plan.fields[2][cross] == 1
    checker.verify(plan, source, boolean_corrections=True)
    broken = deepcopy(plan)
    del broken.fields[2][cross]
    with pytest.raises(ValueError, match="field polynomial identity"):
        checker.verify(broken, source, boolean_corrections=True)


def test_proof_requires_explicit_matching_domain_mode() -> None:
    source = squared_correction("add")
    plain = compiler.compile_plan(source)
    reduced = compiler.compile_plan(source, boolean_corrections=True)
    with pytest.raises(ValueError, match="proof mode does not match"):
        checker.verify(reduced, source)
    with pytest.raises(ValueError, match="proof mode does not match"):
        checker.verify(plain, source, boolean_corrections=True)
    with pytest.raises(ValueError, match="Boolean correction proof mode"):
        checker.verify(reduced, source, boolean_corrections=1)
    with pytest.raises(ValueError, match="Boolean correction mode"):
        compiler.compile_plan(source, boolean_corrections=1)


def test_nonmultilinear_read_cannot_hide_an_unresolved_correction() -> None:
    source = squared_correction("subtract")
    plan = compiler.compile_plan(source, boolean_corrections=True)
    error = next(v for v, b in enumerate(plan.bindings) if b.kind == "correction")
    broken = deepcopy(plan)
    # This added polynomial vanishes on the two-value domain, but executing
    # its original monomials would read the current correction prematurely.
    guard = broken.guards[0]
    before = dict(guard.before)
    before[((error, 2),)] = 1
    before[((error, 1),)] = P - 47
    broken = replace(broken, guards=(replace(guard, before=before),))
    with pytest.raises(ValueError, match="multilinear"):
        checker.verify(broken, source, boolean_corrections=True)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_321_programs_have_checked_multilinear_correction_plans(cap: int) -> None:
    sources = [p for s in recover() for p in s.choices] + [tail_program()]
    field_identities = 0
    guard_identities = 0
    for source in sources:
        plain = compiler.compile_plan(source, cap)
        plan = compiler.compile_plan(source, cap, boolean_corrections=True)
        assert compiler.formula_size(plan) <= compiler.formula_size(plain)
        cert = checker.verify(plan, source, boolean_corrections=True)
        field_identities += cert.field_identities
        guard_identities += cert.guard_identities
        errors = {v for v, b in enumerate(plan.bindings) if b.kind == "correction"}
        polys = (*plan.fields.values(), *plan.anchors, *(p for g in plan.guards for p in (g.before, *g.operands)))
        assert all(e == 1 for poly in polys for monomial in poly for v, e in monomial if v in errors)
    assert (field_identities, guard_identities) == (58486, 62361)


def test_all_scalar_branches_preserve_exact_outputs_and_carry_events() -> None:
    rng = random.Random(20047)
    for stage in recover():
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, boolean_corrections=True)
            for value in (1, P + 1, None):
                state = {s: rng.getrandbits(160) if value is None else value for s in plan.input_slots}
                result = compiler.evaluate(plan, state, stage.index, bit)
                expected, events = evaluate_stage(stage.index, state, bit)
                assert result.outputs == expected and result.defects == events, (stage.index, bit, value)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_complete_byte_and_boundary_controls_with_constrained_proofs(cap: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    cases = [(x, y, 0, scalar_xor_mask())]
    # The carry example changes the actual point, not just projective scale.
    cases.append(((1 << 128) + 48, 917984300236617229462155822449362250189314875415, 0, 0))
    for x, y, prng1, scalar in cases:
        expected, plain = compiler.full_output(x, y, prng1, scalar, cap)
        actual, reduced = compiler.full_output(x, y, prng1, scalar, cap, boolean_corrections=True, verify_algebra=True)
        assert actual == expected
        assert [r.outputs for r in reduced] == [r.outputs for r in plain]
        assert [r.defects for r in reduced] == [r.defects for r in plain]


def test_constrained_checker_does_not_call_compiler_algebra_or_domain_reducer() -> None:
    source = squared_correction("add")
    plan = compiler.compile_plan(source, boolean_corrections=True)
    with (
        patch.object(compiler, "product", side_effect=AssertionError("compiler algebra")),
        patch.object(compiler, "combine", side_effect=AssertionError("compiler algebra")),
        patch.object(compiler, "reduce_correction_powers", side_effect=AssertionError("compiler domain reducer")),
        patch.object(compiler, "validate_order", side_effect=AssertionError("compiler validator")),
    ):
        assert checker.verify(plan, source, boolean_corrections=True).field_identities == 2


def test_domain_identity_does_not_claim_arbitrary_error_equivalence() -> None:
    # An error weight is not necessarily a unit, nor assumed prime-field data.
    for weight in (47, (94 - (1 << 128)) % P):
        for exponent in (2, 3, 16, 129):
            assert all(pow(error, exponent, P) == pow(weight, exponent - 1, P) * error % P for error in (0, weight))
        assert pow(1, 2, P) != weight * 1 % P
