"""Source-derived joint correction domains and independent certificates."""

import random
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_stage_plan as compiler
from tools import scalar_structural_guards as analysis
from tools import verify_scalar_stage_algebra as checker
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import tail_program, model as reference

P = compiler.P


def coupled() -> Program:
    instructions = (
        Instruction(0, 0, 3, "add", (Operand("input", 0), Operand("input", 1)), 0),
        Instruction(1, 1, 4, "subtract", (Operand("value", 0), Operand("input", 2)), 0),
        Instruction(2, 2, 5, "multiply", (Operand("value", 0), Operand("value", 1)), 0),
    )
    return Program(0, 3, 6, 0, instructions, ((5, Operand("value", 2)),))


def independent() -> Program:
    instructions = (
        Instruction(0, 0, 4, "subtract", (Operand("input", 0), Operand("input", 1)), 0),
        Instruction(1, 1, 5, "subtract", (Operand("input", 2), Operand("input", 3)), 0),
        Instruction(2, 2, 6, "multiply", (Operand("value", 0), Operand("value", 1)), 0),
    )
    return Program(0, 3, 7, 0, instructions, ((6, Operand("value", 2)),))


def test_only_proved_joint_error_products_are_removed() -> None:
    source = coupled()
    base = compiler.compile_plan(source, boolean_corrections=True)
    reduced = compiler.compile_plan(source, boolean_corrections=True, exclusive_corrections=True)
    errors = tuple(v for v, b in enumerate(reduced.bindings) if b.kind == "correction")
    term = tuple((v, 1) for v in errors)
    assert base.fields[2][term] == 1 and term not in reduced.fields[2]
    cert = checker.verify(reduced, source, boolean_corrections=True, exclusive_corrections=True)
    assert cert.exclusive_correction_pairs == ((0, 1),)
    for state in ({0: 0, 1: 0, 2: P + 1}, {0: P + 23, 1: P + 24, 2: P + 46}):
        old = compiler.evaluate(base, state)
        actual = compiler.evaluate(reduced, state)
        assert actual.outputs == old.outputs and actual.defects == old.defects
        assert len(actual.defects) == 1


def test_independent_true_errors_keep_their_mixed_term() -> None:
    source = independent()
    plan = compiler.compile_plan(source, boolean_corrections=True, exclusive_corrections=True)
    errors = tuple(v for v, b in enumerate(plan.bindings) if b.kind == "correction")
    term = tuple((v, 1) for v in errors)
    assert plan.fields[2][term] == 1
    checker.verify(plan, source, boolean_corrections=True, exclusive_corrections=True)
    result = compiler.evaluate(plan, {0: 1, 1: P + 2, 2: 1, 3: P + 2})
    assert len(result.defects) == 2 and result.outputs == {6: 2116}
    broken = deepcopy(plan)
    del broken.fields[2][term]
    with pytest.raises(ValueError, match="polynomial identity"):
        checker.verify(broken, source, boolean_corrections=True, exclusive_corrections=True)


def test_checker_rederives_constraints_without_compiler_analyzer_or_algebra() -> None:
    source = coupled()
    plan = compiler.compile_plan(source, boolean_corrections=True, exclusive_corrections=True)
    with (
        patch.object(analysis, "analyze", side_effect=AssertionError("compiler analyzer")),
        patch.object(compiler, "product", side_effect=AssertionError("compiler algebra")),
        patch.object(compiler, "reduce_correction_powers", side_effect=AssertionError("compiler reducer")),
    ):
        assert checker.verify(plan, source, boolean_corrections=True, exclusive_corrections=True).exclusive_correction_pairs
    source = independent()
    facts = analysis.analyze(source, compiler.constant)
    compiler.compile_plan.cache_clear()
    with patch.object(analysis, "analyze", return_value=replace(facts, exclusive=frozenset(((0, 1),)))):
        wrong = compiler.compile_plan(source, boolean_corrections=True, exclusive_corrections=True)
    compiler.compile_plan.cache_clear()
    with pytest.raises(ValueError, match="polynomial identity"):
        checker.verify(wrong, source, boolean_corrections=True, exclusive_corrections=True)


def test_constraints_require_explicit_matching_modes() -> None:
    source = coupled()
    reduced = compiler.compile_plan(source, boolean_corrections=True, exclusive_corrections=True)
    for mode in (False, 1):
        with pytest.raises(ValueError, match="exclusive correction proof mode"):
            checker.verify(reduced, source, boolean_corrections=True, exclusive_corrections=mode)
    with pytest.raises(ValueError, match="require Boolean"):
        compiler.compile_plan(source, exclusive_corrections=True)
    with pytest.raises(ValueError, match="cannot be erased"):
        compiler.reduce_correction_powers(reduced)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_every_program_has_independent_joint_domain_certificates(cap: int) -> None:
    certificates = []
    for source in (*(s for stage in recover() for s in stage.choices), tail_program()):
        base = compiler.compile_plan(source, cap, boolean_corrections=True)
        plan = compiler.compile_plan(source, cap, boolean_corrections=True, exclusive_corrections=True)
        assert compiler.formula_size(plan) <= compiler.formula_size(base)
        cert = checker.verify(plan, source, boolean_corrections=True, exclusive_corrections=True)
        certificates.append(cert)
    assert sum(c.field_identities for c in certificates) == 58486
    assert sum(c.guard_identities for c in certificates) == 62361
    assert sum(len(c.exclusive_correction_pairs) for c in certificates) == 8353


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_both_branches_at_every_stage_retain_exact_defects(cap: int) -> None:
    rng = random.Random(976328)
    for stage in recover():
        states = [{s: v for s in stage.inputs} for v in (0, 1, P, P + 23, P + 46)]
        states.append({s: rng.choice((0, 46, 47, P - 1, P, P + 23)) for s in stage.inputs})
        states.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, cap, boolean_corrections=True, exclusive_corrections=True)
            for state in states:
                outputs, events = evaluate_stage(stage.index, state, bit)
                actual = compiler.evaluate(plan, state, stage.index, bit, structural_guards=True, category_lifts=True)
                assert actual.outputs == outputs and actual.defects == events


@pytest.mark.parametrize("cofactors", [False, True])
def test_full_bytes_boundaries_and_point_changing_control(cofactors: bool) -> None:
    public = tuple(int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    changing = ((1 << 128) + 48, 917984300236617229462155822449362250189314875415)
    kwargs = {"boolean_corrections": True, "demand_guards": cofactors, "cofactor_fields": cofactors, "structural_guards": True}
    for (x, y), scalar in ((public, scalar_xor_mask()), (changing, 0)):
        baseline, old = compiler.full_output(x, y, 0, scalar, **kwargs)
        actual, new = compiler.full_output(x, y, 0, scalar, exclusive_corrections=True, verify_algebra=True, **kwargs)
        expected = reference(bytes(20), scalar.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
        assert actual == baseline == expected.destination
        assert tuple(row.outputs for row in new) == tuple(row.outputs for row in old)
