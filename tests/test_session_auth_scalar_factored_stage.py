"""Factored field DATA preserves complete carry/lift and byte behavior."""

import random
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_compiled_stage as original
from tools import scalar_factored_stage as model
from tools import scalar_field_circuit as circuit
from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import tail_program

P = original.P


def test_multiple_defects_and_mixed_terms_survive_factoring() -> None:
    source = Program(
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
    stage = original.compile_stage(source, exclusive_corrections=True)
    lowered = model.factor_stage(stage)
    assert model.verify(lowered, stage).identities == len(stage.fields)
    actual = model.evaluate(lowered, {0: 1, 1: P + 2, 2: 1, 3: P + 2})
    assert actual.outputs == {6: 2116} and len(actual.defects) == 2
    assert not lowered.equations.sites and not any(lowered.equations.fields)


@pytest.mark.parametrize("cap", [2, 256])
def test_all_320_factored_branches_keep_post_defect_outputs_and_events(cap: int) -> None:
    rng = random.Random(169427)
    for row in recover():
        states = [{s: v for s in row.inputs} for v in (0, 1, 47, P + 1, P + 46)]
        states.append({s: rng.choice((0, 46, 47, P - 1, P, P + 23)) for s in row.inputs})
        states.append({s: rng.randrange(1 << 160) for s in row.inputs})
        for bit, source in enumerate(row.choices):
            stage = original.compile_stage(source, cap, exclusive_corrections=True)
            lowered = model.factor_stage(stage)
            for state in states:
                expected, events = evaluate_stage(row.index, state, bit)
                actual = model.evaluate(lowered, state, row.index, bit)
                assert actual.outputs == expected and actual.defects == events


def test_factored_runtime_has_no_polynomial_source_or_helper_replay() -> None:
    row = recover()[1]
    stage = original.compile_stage(row.choices[0], exclusive_corrections=True)
    lowered = model.factor_stage(stage)
    state = {s: P + 1 for s in row.inputs}
    expected, events = evaluate_stage(1, state, 0)
    with (
        patch.object(circuit.Builder, "compile", side_effect=AssertionError("field factoring")),
        patch.object(original, "compile_stage", side_effect=AssertionError("source compiler")),
        patch.object(compiler, "compile_plan", side_effect=AssertionError("field compiler")),
        patch.object(compiler, "constant", side_effect=AssertionError("source constants")),
        patch.object(compiler, "evaluate", side_effect=AssertionError("source tag interpreter")),
        patch.object(exact, "execute_program", side_effect=AssertionError("source arithmetic")),
        patch.object(rules, "add", side_effect=AssertionError("source arithmetic")),
        patch.object(rules, "subtract", side_effect=AssertionError("source arithmetic")),
        patch.object(rules, "multiply", side_effect=AssertionError("source arithmetic")),
        patch.object(rules, "lazy_addition_defect", side_effect=AssertionError("carry helper")),
        patch.object(rules, "lazy_subtraction_defect", side_effect=AssertionError("carry helper")),
    ):
        actual = model.evaluate(lowered, state, 1, 0)
        assert actual.outputs == expected and actual.defects == events


def test_factored_finalizer_keeps_iterative_cap_two_anchor_scheduling() -> None:
    stage = original.compile_stage(tail_program(), 2, exclusive_corrections=True)
    lowered = model.factor_stage(stage)
    for a, b in ((0, 0), (P, 1), (P + 1, P + 23), (123, 456)):
        actual = model.evaluate(lowered, {5: a, 87: b})
        expected = original.evaluate(stage, {5: a, 87: b})
        assert actual.outputs == expected.outputs and actual.defects == expected.defects
        # Factoring changes demand order; counters are not equivalence outputs.
        assert actual.anchors_evaluated > 2000


def test_mutations_of_actual_factor_data_metadata_and_certificate_are_rejected() -> None:
    stage = original.compile_stage(recover()[32].choices[0], exclusive_corrections=True)
    lowered = model.factor_stage(stage)
    roots = list(lowered.kernel.roots)
    field = next(i for i, terms in enumerate(stage.fields) if terms)
    roots[field] = 0
    with pytest.raises(ValueError, match="identity"):
        model.verify(replace(lowered, kernel=replace(lowered.kernel, roots=tuple(roots))), stage)
    guard = lowered.equations.guards[0]
    broken = replace(lowered.equations, guards=(replace(guard, correction=1), *lowered.equations.guards[1:]))
    with pytest.raises(ValueError, match="metadata"):
        model.verify(replace(lowered, equations=broken), stage)
    with pytest.raises(ValueError, match="certificate"):
        model.verify(replace(lowered, certificate=replace(lowered.certificate, data_sha256="0" * 64)), stage)
    with pytest.raises(ValueError, match="inventory"):
        original.evaluate(lowered.equations, {s: 0 for s in stage.input_slots}, field_kernel=replace(lowered.kernel, roots=()))
    with pytest.raises(ValueError, match="require their field kernel"):
        original.evaluate(lowered.equations, {s: 0 for s in stage.input_slots})


def test_shared_predicate_projection_is_checked_without_the_sharing_builder() -> None:
    stage = original.compile_stage(recover()[1].choices[0], 2, exclusive_corrections=True)
    lowered = model.factor_stage(stage)
    with (
        patch.object(model, "_share", side_effect=AssertionError("sharing builder")),
        patch.object(model.Backend, "node", side_effect=AssertionError("predicate frontend")),
    ):
        model.verify(lowered, stage)
    broken = deepcopy(lowered)
    root = next(i for i, n in enumerate(broken.equations.predicates.nodes) if n.operation == "field")
    broken.equations.predicates.nodes[root] = model.Node("field", (10_000_000,))
    with pytest.raises(ValueError, match="projection"):
        model.verify(broken, stage)
    broken = deepcopy(lowered)
    broken.equations.predicates.bounds[root] = (0, 0)
    with pytest.raises(ValueError, match="metadata"):
        model.verify(broken, stage)
    with pytest.raises(ValueError, match="predicate certificate"):
        model.verify(replace(lowered, predicates=replace(lowered.predicates, data_sha256="0" * 64)), stage)


@pytest.mark.parametrize("cap,field_count", [(2, 87_191), (256, 66_432)])
def test_globally_shared_circuit_keeps_all_bytes_boundaries_and_full_defect_traces(cap: int, field_count: int) -> None:
    catalogue = original.compile_catalogue(cap, exclusive_corrections=True, verify_data=True)
    lowered = model.factor_catalogue(catalogue)
    stages = tuple(s for pair in lowered.choices for s in pair) + (lowered.tail,)
    assert all(s.kernel.circuit is lowered.tail.kernel.circuit for s in stages)
    assert all(s.equations.predicates is lowered.tail.equations.predicates for s in stages)
    assert not lowered.tail.equations.predicates.interned
    assert sum(s.certificate.identities for s in stages) == field_count
    assert all(not any(s.equations.fields) and not s.equations.sites for s in stages)
    for index in (0, 1, 16, 32, 80, 159):
        for bit in (0, 1):
            model.verify(lowered.choices[index][bit], catalogue.choices[index][bit])
    model.verify(lowered.tail, catalogue.tail)
    public = tuple(int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    changing = ((1 << 128) + 48, 917984300236617229462155822449362250189314875415)
    cases = []
    for (x, y), scalar in ((public, scalar_xor_mask()), (changing, 0)):
        expected, old = original.full_output(catalogue, x, y, 0, scalar)
        cases.append((x, y, scalar, expected, old))
    del catalogue  # No original polynomials or site inventory needed now.
    with (
        patch.object(circuit.Builder, "compile", side_effect=AssertionError("field factor compiler")),
        patch.object(original, "compile_stage", side_effect=AssertionError("source compiler")),
        patch.object(compiler, "compile_plan", side_effect=AssertionError("field compiler")),
        patch.object(compiler, "constant", side_effect=AssertionError("source constants")),
        patch.object(exact, "execute_program", side_effect=AssertionError("source arithmetic interpreter")),
    ):
        for x, y, scalar, expected, old in cases:
            result, rows = model.full_output(lowered, x, y, 0, scalar)
            assert result == expected and len(result) == 72 and len(rows) == 161
            assert tuple((r.outputs, r.defects) for r in rows) == tuple((r.outputs, r.defects) for r in old)
