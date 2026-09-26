"""Complete equation-only stages, post-defect tags and data certificates."""

import random
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_compiled_stage as model
from tools import scalar_stage_plan as compiler
from tools import scalar_representative_rules as rules
from tools import scalar_lift_categories as categories
from tools import scalar_constant_lifts as constants
from tools import transform12_integer_model as exact
from tools import verify_scalar_compiled_stage as checker
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference, tail_program

P = model.P


def two_defects() -> Program:
    return Program(
        0,
        3,
        7,
        0,
        (
            Instruction(0, 0, 4, "subtract", (Operand("input", 0), Operand("input", 1)), 0),
            Instruction(1, 1, 5, "subtract", (Operand("input", 2), Operand("input", 3)), 0),
            Instruction(2, 2, 6, "multiply", (Operand("value", 0), Operand("value", 1)), 0),
        ),
        ((6, Operand("value", 2)),),
    )


def test_multiple_defects_are_not_a_prefix_only_model() -> None:
    source = two_defects()
    stage = model.compile_stage(source, exclusive_corrections=True)
    checker.verify(stage, source)
    result = model.evaluate(stage, {0: 1, 1: P + 2, 2: 1, 3: P + 2})
    assert len(result.defects) == 2 and result.outputs == {6: 2116}


def test_evaluation_has_no_source_interpreter_or_arithmetic_callback() -> None:
    row = recover()[1]
    stage = model.compile_stage(row.choices[0], exclusive_corrections=True)
    state = {s: P + 1 for s in row.inputs}
    expected, events = evaluate_stage(1, state, 0)
    with (
        patch.object(compiler, "compile_plan", side_effect=AssertionError("source compiler")),
        patch.object(compiler, "constant", side_effect=AssertionError("source constant lookup")),
        patch.object(compiler, "evaluate", side_effect=AssertionError("source tag interpretation")),
        patch.object(exact, "execute_program", side_effect=AssertionError("source arithmetic interpreter")),
        patch.object(rules, "add", side_effect=AssertionError("arithmetic callback")),
        patch.object(rules, "subtract", side_effect=AssertionError("arithmetic callback")),
        patch.object(rules, "multiply", side_effect=AssertionError("arithmetic callback")),
        patch.object(rules, "lazy_addition_defect", side_effect=AssertionError("carry callback")),
        patch.object(rules, "lazy_subtraction_defect", side_effect=AssertionError("carry callback")),
        patch.object(categories, "small_addition_lift", side_effect=AssertionError("tag callback")),
        patch.object(categories, "small_subtraction_lift", side_effect=AssertionError("tag callback")),
        patch.object(constants, "lift", side_effect=AssertionError("tag callback")),
    ):
        result = model.evaluate(stage, state, 1, 0)
        assert result.outputs == expected and result.defects == events
    assert not hasattr(stage, "program") and not hasattr(stage, "tag_sources")


def test_data_verifier_does_not_call_stage_compiler_or_compiler_algebra() -> None:
    source = recover()[32].choices[0]
    stage = model.compile_stage(source, exclusive_corrections=True)
    with (
        patch.object(model, "compile_stage", side_effect=AssertionError("stage compiler")),
        patch.object(compiler, "compile_plan", side_effect=AssertionError("field compiler")),
        patch.object(compiler, "constant", side_effect=AssertionError("compiler constants")),
        patch.object(compiler, "carry_safe", side_effect=AssertionError("compiler exclusions")),
        patch.object(compiler, "operation", side_effect=AssertionError("compiler algebra")),
        patch.object(compiler, "product", side_effect=AssertionError("compiler algebra")),
    ):
        verified = checker.verify(stage, source)
    assert verified.lift_contracts == len(source.instructions)


def test_mutations_of_actual_compiled_fields_carries_tags_and_outputs_are_rejected() -> None:
    source = two_defects()
    stage = model.compile_stage(source, exclusive_corrections=True)
    fields = list(stage.fields)
    root = stage.sites[-1].field
    first = dict(fields[root])
    monomial = next(iter(first))
    first[monomial] = first[monomial] * 2 % P
    fields[root] = tuple(sorted(first.items()))
    with pytest.raises(ValueError, match="identity|coefficient"):
        checker.verify(replace(stage, fields=tuple(fields)), source)
    false = stage.predicates.expression(False, "boolean").index
    broken_guard = replace(stage.guards[0], predicate=false)
    with pytest.raises(ValueError, match="carry contract"):
        checker.verify(replace(stage, guards=(broken_guard, *stage.guards[1:])), source)
    with pytest.raises(ValueError, match="lift contract"):
        checker.verify(replace(stage, sites=(replace(stage.sites[0], tag=false), *stage.sites[1:])), source)
    with pytest.raises(ValueError, match="provenance|weight"):
        checker.verify(replace(stage, guards=(replace(stage.guards[0], correction=1), *stage.guards[1:])), source)
    with pytest.raises(ValueError, match="output references"):
        checker.verify(replace(stage, outputs=((6, stage.outputs[0][1], false),)), source)


def test_compiler_interval_metadata_is_not_trusted_by_data_verifier() -> None:
    source = two_defects()
    stage = deepcopy(model.compile_stage(source))
    field_node = next(i for i, n in enumerate(stage.predicates.nodes) if n.operation == "field")
    stage.predicates.bounds[field_node] = (0, 0)
    with pytest.raises(ValueError, match="metadata mismatch"):
        checker.verify(stage, source)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_321_equation_data_sets_have_independent_translation_validation(cap: int) -> None:
    verifications = []
    for source in (*(p for row in recover() for p in row.choices), tail_program()):
        stage = model.compile_stage(source, cap, exclusive_corrections=True)
        verifications.append(checker.verify(stage, source))
    assert sum(v.coefficients.field_identities for v in verifications) == 58486
    assert sum(v.coefficients.guard_identities for v in verifications) == 62361
    assert sum(v.carry_contracts for v in verifications) == 20787
    assert sum(v.lift_contracts for v in verifications) == 58486


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_320_source_branches_have_exact_post_defect_outputs_and_events(cap: int) -> None:
    rng = random.Random(124736)
    for row in recover():
        states = [{s: v for s in row.inputs} for v in (0, 1, 23, 47, P, P + 1, P + 46)]
        states.append({s: rng.choice((0, 46, 47, P - 1, P, P + 23)) for s in row.inputs})
        states.append({s: rng.randrange(1 << 160) for s in row.inputs})
        for bit, source in enumerate(row.choices):
            compiled = model.compile_stage(source, cap, exclusive_corrections=True)
            for state in states:
                expected, events = evaluate_stage(row.index, state, bit)
                actual = model.evaluate(compiled, state, row.index, bit)
                assert actual.outputs == expected and actual.defects == events


def test_cap_two_tail_needs_no_recursive_anchor_or_tag_history() -> None:
    source = tail_program()
    stage = model.compile_stage(source, 2, exclusive_corrections=True)
    for a, b in ((0, 0), (P, 1), (P + 1, P + 23), (123, 456)):
        state = {5: a, 87: b}
        actual = model.evaluate(stage, state)
        baseline = compiler.evaluate(
            compiler.compile_plan(source, 2, boolean_corrections=True, exclusive_corrections=True), state
        )
        assert actual.outputs == baseline.outputs and actual.defects == baseline.defects


@pytest.mark.parametrize("domains", [(False, False), (True, False), (True, True)])
def test_all_supported_field_domain_modes_have_identical_stage_semantics(domains: tuple[bool, bool]) -> None:
    source = recover()[1].choices[0]
    state = {s: P + 1 for s in recover()[1].inputs}
    compiled = model.compile_stage(source, boolean_corrections=domains[0], exclusive_corrections=domains[1])
    checker.verify(compiled, source)
    actual = model.evaluate(compiled, state, 1, 0)
    expected, events = evaluate_stage(1, state, 0)
    assert actual.outputs == expected and actual.defects == events


def test_full_output_bytes_and_boundaries_after_source_free_compilation() -> None:
    catalogue = model.compile_catalogue(exclusive_corrections=True, verify_data=True)
    assert len(catalogue.verifications) == 321
    public = tuple(int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    changing = ((1 << 128) + 48, 917984300236617229462155822449362250189314875415)
    for (x, y), scalar in ((public, scalar_xor_mask()), (changing, 0)):
        expected = reference(bytes(20), scalar.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
        baseline, old = compiler.full_output(x, y, 0, scalar, boolean_corrections=True, exclusive_corrections=True)
        with (
            patch.object(model, "compile_stage", side_effect=AssertionError("source compilation")),
            patch.object(compiler, "evaluate", side_effect=AssertionError("source tag interpretation")),
        ):
            actual, new = model.full_output(catalogue, x, y, 0, scalar)
        assert actual == baseline == expected.destination
        assert tuple(r.outputs for r in new) == tuple(r.outputs for r in old)
        assert tuple(r.defects for r in new) == tuple(r.defects for r in old)


def test_input_scope_and_missing_correction_bindings_fail_closed() -> None:
    source = two_defects()
    compiled = model.compile_stage(source)
    with pytest.raises(ValueError, match="layout"):
        model.evaluate(compiled, {})
    for bad in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="uint160"):
            model.evaluate(compiled, {0: bad, 1: 1, 2: 1, 3: 1})
    guard = replace(compiled.guards[0], fields=compiled.guards[1].fields)
    with pytest.raises(ValueError, match="operands mismatch"):
        checker.verify(replace(compiled, guards=(guard, *compiled.guards[1:])), source)
    with pytest.raises(ValueError, match="Boolean"):
        model.compile_stage(source, verify_algebra=1)
