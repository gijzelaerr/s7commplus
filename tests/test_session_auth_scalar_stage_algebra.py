"""Independent coefficient checks, including anchor aliases and corrupt plans."""

from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from tools import scalar_stage_plan as compiler
from tools import verify_scalar_stage_algebra as checker
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_transform12_phase1 import recover
from tools.transform7_reference import tail_program
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools.recover_scalar_encodings import scalar_xor_mask


def primitive(operation: str = "add") -> Program:
    operands = (Operand("input", 0),) if operation == "square" else (Operand("input", 0), Operand("input", 1))
    instruction = Instruction(0, 0, 2, operation, operands, 0)
    return Program(0, 1, 3, 0, (instruction,), ((2, Operand("value", 0)),))


def shifted(poly: compiler.Polynomial) -> compiler.Polynomial:
    result = dict(poly)
    coefficient = (result.get((), 0) + 1) % checker.MODULUS
    if coefficient:
        result[()] = coefficient
    else:
        result.pop((), None)
    return result


def test_all_320_alternatives_and_fixed_tail_have_exact_coefficient_certificates() -> None:
    programs = [program for stage in recover() for program in stage.choices] + [tail_program()]
    certificates = [checker.verify(compiler.compile_plan(source), source) for source in programs]
    assert len(certificates) == 321
    assert sum(c.field_identities for c in certificates) == 58486
    assert sum(c.guard_identities for c in certificates) == 62361
    assert all(c.field_identities == c.source_instructions for c in certificates)
    assert all(c.guard_identities == 3 * len(compiler.compile_plan(source).guards) for c, source in zip(certificates, programs))
    assert len({c.constant_table_sha256 for c in certificates}) == 1
    assert all(len(c.source_sha256) == len(c.plan_sha256) == 64 for c in certificates)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_difficult_initial_and_tail_groups_at_each_anchor_bound(cap: int) -> None:
    for source in (recover()[0].choices[0], tail_program()):
        plan = compiler.compile_plan(source, cap)
        certificate = checker.verify(plan, source)
        assert certificate.anchors == len(plan.anchors) > 0


def test_reused_operand_anchor_is_not_treated_as_an_independent_symbol() -> None:
    # Tail SSA74 reuses an old anchor equal to the first operand; that
    # symbol also occurs inside the second operand. Treating all operand
    # anchors as independent incorrectly rejects this valid identity.
    tail = tail_program()
    instructions = tuple(i for i in tail.instructions if i.value <= 74)
    source = replace(tail, instructions=instructions, outputs=((5, Operand("value", 74)),))
    plan = compiler.compile_plan(source)
    first_operand = plan.fields[43]
    assert first_operand in plan.anchors
    assert checker.verify(plan, source).field_identities == len(instructions)
    invalid = deepcopy(plan)
    invalid.fields[74] = shifted(invalid.fields[74])
    with pytest.raises(ValueError, match="identity failed"):
        checker.verify(invalid, source)


@pytest.mark.parametrize("operation", ["add", "subtract", "multiply", "square"])
def test_checker_does_not_use_compiler_algebra_or_validation_helpers(operation: str) -> None:
    ordinary = primitive(operation)
    instruction = ordinary.instructions[0]
    operands = (*instruction.operands[:-1], Operand("constant", 1))
    constant_source = replace(ordinary, instructions=(replace(instruction, operands=operands),))
    for source in (ordinary, constant_source):
        plan = compiler.compile_plan(source)
        with (
            patch.object(compiler, "combine", side_effect=AssertionError("compiler algebra")),
            patch.object(compiler, "product", side_effect=AssertionError("compiler algebra")),
            patch.object(compiler, "operation", side_effect=AssertionError("compiler algebra")),
            patch.object(compiler, "fixed", side_effect=AssertionError("compiler constants")),
            patch.object(compiler, "constant", side_effect=AssertionError("compiler constants")),
            patch.object(compiler, "carry_safe", side_effect=AssertionError("compiler exclusions")),
            patch.object(compiler, "validate_order", side_effect=AssertionError("compiler structure")),
            patch.object(checker, "compile_plan", side_effect=AssertionError("recompilation")),
        ):
            assert checker.verify(plan, source).field_identities == 1


@pytest.mark.parametrize("operation", ["add", "subtract", "multiply", "square"])
def test_wrong_field_coefficients_fail_for_every_primitive(operation: str) -> None:
    source = primitive(operation)
    plan = deepcopy(compiler.compile_plan(source))
    plan.fields[0] = shifted(plan.fields[0])
    with pytest.raises(ValueError, match="field polynomial identity failed"):
        checker.verify(plan, source)


@pytest.mark.parametrize("part", ["before", "first", "second"])
def test_wrong_guard_equations_fail(part: str) -> None:
    source = primitive()
    plan = compiler.compile_plan(source)
    guard = plan.guards[0]
    if part == "before":
        guard = replace(guard, before=shifted(guard.before))
    else:
        operands = list(guard.operands)
        index = 0 if part == "first" else 1
        operands[index] = shifted(operands[index])
        guard = replace(guard, operands=tuple(operands))
    with pytest.raises(ValueError, match="guard polynomial identity failed"):
        checker.verify(replace(plan, guards=(guard,)), source)


def test_wrong_correction_weight_fails_even_when_the_frontier_is_valid() -> None:
    source = primitive()
    plan = deepcopy(compiler.compile_plan(source))
    error_id = next(v for v, binding in enumerate(plan.bindings) if binding.kind == "correction")
    plan.fields[0][((error_id, 1),)] = 2
    compiler.validate_order(plan)  # Structure alone cannot detect this.
    with pytest.raises(ValueError, match="identity failed"):
        checker.verify(plan, source)


@pytest.mark.parametrize("count", [0, 1, 3])
def test_missing_or_extra_guard_operand_equations_fail_closed(count: int) -> None:
    source = primitive()
    plan = compiler.compile_plan(source)
    guard = replace(plan.guards[0], operands=(plan.guards[0].operands[0],) * count)
    with pytest.raises(ValueError, match="exactly two operand equations"):
        checker.verify(replace(plan, guards=(guard,)), source)


def test_changed_anchor_definition_is_rejected_algebraically() -> None:
    source = recover()[0].choices[0]
    plan = deepcopy(compiler.compile_plan(source, 2))
    first = plan.anchors[0]
    monomial = next(iter(first))
    first[monomial] = first[monomial] * 2 % checker.MODULUS
    compiler.validate_order(plan)
    with pytest.raises(ValueError):
        checker.verify(plan, source)


def test_separately_supplied_source_and_inventories_are_required() -> None:
    source = primitive()
    plan = compiler.compile_plan(source)
    with pytest.raises(ValueError, match="supplied source"):
        checker.verify(plan, replace(source, start=99))
    with pytest.raises(ValueError, match="guard inventory"):
        checker.verify(replace(plan, guards=()), source)
    with pytest.raises(ValueError, match="field/tag inventory"):
        checker.verify(replace(plan, fields={}), source)
    with pytest.raises(ValueError, match="exclusion count"):
        checker.verify(replace(plan, excluded_guards=1), source)
    with pytest.raises(ValueError, match="frontier mismatch"):
        checker.verify(replace(plan, frontiers=(99,) * len(plan.frontiers)), source)


def test_future_correction_and_anchor_cycle_fail_closed() -> None:
    source = primitive()
    plan = compiler.compile_plan(source)
    error_id = next(v for v, binding in enumerate(plan.bindings) if binding.kind == "correction")
    guard = replace(plan.guards[0], before={((error_id, 1),): 1})
    with pytest.raises(ValueError, match="unresolved correction"):
        checker.verify(replace(plan, guards=(guard,)), source)
    source = recover()[0].choices[0]
    plan = compiler.compile_plan(source, 2)
    anchor_id = next(v for v, binding in enumerate(plan.bindings) if binding.kind == "anchor")
    anchors = list(plan.anchors)
    anchors[0] = {((anchor_id, 1),): 1}
    with pytest.raises(ValueError, match="forward formula variable"):
        checker.verify(replace(plan, anchors=tuple(anchors)), source)


@pytest.mark.parametrize("coefficient", [0, -1, checker.MODULUS, True])
def test_noncanonical_coefficients_fail_closed(coefficient: int) -> None:
    source = primitive("square")
    plan = deepcopy(compiler.compile_plan(source))
    plan.fields[0] = {((0, 2),): coefficient}
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        checker.verify(plan, source)


def test_resource_exhaustion_is_not_a_probabilistic_success() -> None:
    source = primitive("multiply")
    plan = compiler.compile_plan(source)
    with patch.object(checker, "WORK_LIMIT", 0):
        with pytest.raises(ValueError, match="work budget"):
            checker.verify(plan, source)
    with pytest.raises(ValueError, match="exponent budget"):
        checker._power({frozenset(((0, 1),)): 1}, 1 << 4096)


def test_optional_verification_checks_every_selected_plan_before_evaluation() -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    scalar = scalar_xor_mask()
    expected, _ = compiler.full_output(x, y, 0, scalar)
    with patch.object(checker, "verify", wraps=checker.verify) as verified:
        actual, rows = compiler.full_output(x, y, 0, scalar, verify_algebra=True)
    assert actual == expected and verified.call_count == len(rows) == 161
    with (
        patch.object(checker, "verify", side_effect=ValueError("invalid algebra")),
        patch.object(compiler, "evaluate", side_effect=AssertionError("unverified execution")),
    ):
        with pytest.raises(ValueError, match="invalid algebra"):
            compiler.full_output(x, y, 0, scalar, verify_algebra=True)
