"""Exact raw saturation, independently checked history, full-output controls."""

import random
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import scalar_compiled_stage as old
from tools import scalar_saturated_history as model
from tools import scalar_stage_plan as compiler
from tools import scalar_representative_rules as rules
from tools import transform12_integer_model as exact
from tools import transform7_reference as reference_module
from tools import trace_scalar_seed_boundary as seed_boundary
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.prove_scalar_saturated_history import prove
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference, tail_program

P = model.P


@pytest.fixture(scope="module", params=[2, 256])
def catalogue(request: pytest.FixtureRequest) -> model.Catalogue:
    return model.catalogue(request.param)


def test_actual_source_ast_exact_saturation_obligations() -> None:
    pytest.importorskip("z3")
    result = prove()
    assert result["full_proof"]
    assert len(result["obligations"]) == 15
    assert [r["result"] for r in result["obligations"]].count("unsat") == 14
    with pytest.raises(ValueError, match="positive"):
        prove(0)


def test_multiplication_trees_collapse_exactly_and_domain_is_minimal() -> None:
    from itertools import product

    samples = (0, 1, 6, 7, 46, 47, P - 1, P, P + 1, P + 46)
    for a, b, c in product(samples, repeat=3):
        assert model.product((a, b, c)) == exact.multiply(exact.multiply(a, b), c)
        assert model.product((a, b, c)) == exact.multiply(a, exact.multiply(b, c))
    assert model.product(()) == 1 and model.product((P + 1,)) == P + 1
    for bad in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="uint160"):
            model.product((bad,))
    # All48 states are distinguishable by a nonnegative addition context and
    # the raw>=47 observation. A smaller context-independent quotient cannot
    # retain that observation for arbitrary positive-semiring expressions.
    for smaller in range(47):
        for larger in range(smaller + 1, 48):
            context = 47 - larger
            assert min(smaller + context, 47) < 47 == min(larger + context, 47)


def test_exact_saturation_is_not_the_old_lower_bound() -> None:
    source = Program(
        0,
        1,
        3,
        0,
        (Instruction(0, 0, 2, "subtract", (Operand("input", 0), Operand("input", 1)), 0),),
        ((2, Operand("value", 0)),),
    )
    original = old.compile_stage(source)
    stage = model.lower(source, original)
    model.verify(stage, source, original)
    assert model.evaluate(stage, {0: 0, 1: P + 1}).outputs == {2: P + 46}
    assert model.evaluate(stage, {0: 48, 1: 47}).outputs == {2: 1}
    # Both operands have saturation47 in the second case; subtracting their
    # saturations would give zero, not the exact output saturation1.
    assert model.saturation_value(stage.nodes, stage.outputs[0][2], (48, 47), lambda _: 1, {}) == 1


def test_complete_catalogue_has_no_boolean_or_source_history(catalogue: model.Catalogue) -> None:
    assert len(catalogue.certificates) == 321
    assert sum(c.source_values for c in catalogue.certificates) == 58486
    assert len(catalogue.tail.nodes) < 35000
    for stage in [s for pair in catalogue.choices for s in pair] + [catalogue.tail]:
        assert stage.nodes is catalogue.tail.nodes
        assert not hasattr(stage, "predicates") and not hasattr(stage, "program")


def test_all_320_branches_match_raw_outputs_and_complete_events(catalogue: model.Catalogue) -> None:
    rng = random.Random(470160)
    for row, pair in zip(recover(), catalogue.choices):
        samples = [{s: v for s in row.inputs} for v in (0, 1, 6, 7, 23, 46, 47, P - 1, P, P + 1, P + 46)]
        samples.extend({s: rng.choice((0, 23, 46, 47, P - 1, P, P + 23)) for s in row.inputs} for _ in range(2))
        samples.append({s: rng.randrange(1 << 160) for s in row.inputs})
        for bit, stage in enumerate(pair):
            for state in samples:
                expected, events = evaluate_stage(row.index, state, bit)
                actual = model.evaluate(stage, state, row.index, bit)
                assert actual.outputs == expected and actual.defects == events


def test_every_source_site_saturation_is_exact_not_just_a_bound() -> None:
    rng = random.Random(470321)
    for row in recover():
        for source in row.choices:
            original = old.compile_stage(source, 2)
            stage = model.lower(source, original)
            for state in ({s: P + 23 for s in row.inputs}, {s: rng.choice((0, 1, 46, 47, P + 1)) for s in row.inputs}):
                values = {}

                def resolve(o: Operand) -> int:
                    if o.kind == "input":
                        return state[o.index]
                    if o.kind == "value":
                        return values[o.index]
                    return exact.decode(TRANSFORM12_BIG_INT_DATA[o.index * 24 : (o.index + 1) * 24])

                for i in source.instructions:
                    a, b = resolve(i.operands[0]), resolve(i.operands[-1])
                    operation = {
                        "add": exact.add,
                        "subtract": exact.subtract,
                        "multiply": exact.multiply,
                        "square": exact.multiply,
                    }[i.operation]
                    values[i.value] = operation(a, b)
                fields = {site.field: values[site.value] % P for site in original.sites}
                for ordinal, terms in enumerate(original.fields):
                    if not terms or all(not powers for powers, _ in terms):
                        fields[ordinal] = sum(c for _, c in terms) % P
                    elif len(terms) == 1 and terms[0][1] == 1 and len(terms[0][0]) == 1:
                        variable, power = terms[0][0][0]
                        binding = original.variables[variable]
                        if power == 1 and binding.kind == "input":
                            fields[ordinal] = state[original.input_slots[binding.index]] % P
                cache = {}
                raw = tuple(state[s] for s in stage.input_slots)
                for i, root in zip(source.instructions, stage.site_saturations):
                    assert model.saturation_value(stage.nodes, root, raw, fields.__getitem__, cache) == min(values[i.value], 47)


def test_full_72_bytes_all_161_boundaries_and_point_changing_errors(catalogue: model.Catalogue) -> None:
    public = tuple(int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    changing = ((1 << 128) + 48, 917984300236617229462155822449362250189314875415)
    for (x, y), scalar in ((public, scalar_xor_mask()), (changing, 0)):
        expected = reference(bytes(20), scalar.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
        baseline, old_rows = compiler.full_output(x, y, 0, scalar, boolean_corrections=True)
        actual, new_rows = model.full_output(catalogue, x, y, 0, scalar)
        assert len(new_rows) == 161
        assert actual == baseline == expected.destination
        assert tuple(r.outputs for r in new_rows) == tuple(r.outputs for r in old_rows)
        assert tuple(r.defects for r in new_rows) == tuple(r.defects for r in old_rows)
        assert sum(len(r.defects) for r in new_rows) == (3 if (x, y) == public else 30)


def test_saturation_model_preserves_bundled_key_caller_counterexample(catalogue: model.Catalogue) -> None:
    case = seed_boundary.cases()[4]
    original_reference = reference_module.model
    event_counts = []

    def saturated(prng1: bytes, selector: bytes, source: bytes) -> reference_module.Reference:
        x, y = (int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20))
        baseline = original_reference(prng1, selector, source)
        destination, rows = model.full_output(
            catalogue, x, y, int.from_bytes(prng1, "little"), int.from_bytes(selector, "little")
        )
        assert len(rows) == 161
        assert destination == baseline.destination
        if source[:40] == case.public_key:
            scalar_events = tuple(event for row in rows[:160] for event in row.defects)
            assert [(event.stage, event.tape_index) for event in scalar_events] == [(0, 30506), (0, 30523)]
            event_counts.append(len(scalar_events))
        return replace(baseline, destination=destination)

    with patch.object(reference_module, "model", saturated):
        actual = seed_boundary.first_nonce(case, "reference")
    original = seed_boundary.first_nonce(case, "original")
    candidate = seed_boundary.first_nonce(case, "modular")
    assert actual == original and actual.accepted
    assert actual.seed != candidate.seed and candidate.accepted
    assert event_counts == [2]


def test_numerical_phase_does_not_use_old_history_helpers_or_source() -> None:
    source = recover()[1].choices[0]
    original = old.compile_stage(source, 2)
    stage = model.lower(source, original)
    state = {s: P + 1 for s in stage.input_slots}
    expected, events = evaluate_stage(1, state, 0)
    with (
        patch.object(old, "evaluate", side_effect=AssertionError("old history")),
        patch.object(old, "compile_stage", side_effect=AssertionError("source compilation")),
        patch.object(compiler, "constant", side_effect=AssertionError("source constants")),
        patch.object(compiler, "evaluate", side_effect=AssertionError("source tags")),
        patch.object(exact, "execute_program", side_effect=AssertionError("source interpreter")),
        patch.object(rules, "lazy_addition_defect", side_effect=AssertionError("old guard")),
        patch.object(rules, "lazy_subtraction_defect", side_effect=AssertionError("old guard")),
        patch.object(rules, "multiply", side_effect=AssertionError("old primitive")),
    ):
        result = model.evaluate(stage, state, 1, 0)
        assert result.outputs == expected and result.defects == events


def test_verifier_checks_actual_data_without_compiler_or_evaluation() -> None:
    source = recover()[32].choices[0]
    original = old.compile_stage(source, 2)
    stage = model.lower(source, original)
    with (
        patch.object(model, "lower", side_effect=AssertionError("compiler")),
        patch.object(model.Builder, "node", side_effect=AssertionError("builder")),
        patch.object(model, "evaluate", side_effect=AssertionError("sampling")),
        patch.object(compiler, "constant", side_effect=AssertionError("compiler decoder")),
        patch.object(compiler, "compile_plan", side_effect=AssertionError("compiler")),
    ):
        assert model.verify(stage, source, original).source_values == len(source.instructions)


def test_mutations_of_data_roots_bindings_fields_and_edges_fail_closed() -> None:
    source = recover()[32].choices[0]
    original = old.compile_stage(source, 2)
    stage = model.lower(source, original)
    nodes = list(stage.nodes)
    literal = next(i for i, n in enumerate(nodes) if n.operation == "literal" and n.arguments[0] != 0)
    nodes[literal] = model.Node("literal", (48,))
    with pytest.raises(ValueError, match="invalid"):
        model.verify(replace(stage, nodes=tuple(nodes)), source, original)
    roots = (stage.site_saturations[-1], *stage.site_saturations[1:])
    with pytest.raises(ValueError, match="differs"):
        model.verify(replace(stage, site_saturations=roots), source, original)
    guard = replace(stage.guards[0], saturations=(stage.outputs[0][2], stage.outputs[0][2]))
    with pytest.raises(ValueError, match="binding"):
        model.verify(replace(stage, guards=(guard, *stage.guards[1:])), source, original)
    with pytest.raises(ValueError, match="field plane"):
        model.verify(replace(stage, fields=stage.fields[:-1]), source, original)
    with pytest.raises(ValueError, match="output"):
        model.verify(replace(stage, outputs=stage.outputs[:-1]), source, original)
    nodes = list(stage.nodes)
    index = next(i for i, n in enumerate(nodes) if n.operation == "multiply")
    nodes[index] = model.Node("multiply", (index, index))
    with pytest.raises(ValueError, match="future|cyclic"):
        model.verify(replace(stage, nodes=tuple(nodes)), source, original)


def test_multiple_defects_preserve_mixed_nonlinear_interactions() -> None:
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
    original = old.compile_stage(source, 2)
    stage = model.lower(source, original)
    model.verify(stage, source, original)
    result = model.evaluate(stage, {0: 1, 1: P + 2, 2: 1, 3: P + 2})
    assert len(result.defects) == 2 and result.outputs == {6: 2116}


def test_tail_and_deep_saturation_chains_are_iterative() -> None:
    original = old.compile_stage(tail_program(), 2)
    stage = model.lower(tail_program(), original)
    for state in ({5: 0, 87: 0}, {5: P + 1, 87: P + 23}, {5: 123, 87: 456}):
        actual = model.evaluate(stage, state)
        expected = old.evaluate(original, state)
        assert actual.outputs == expected.outputs and actual.defects == expected.defects
    graph = model.Builder()
    root = graph.node("input", (0,))
    other = graph.node("input", (1,))
    for _ in range(2500):
        root = graph.combine("multiply", root, other)
    assert model.saturation_value(tuple(graph.nodes), root, (1, 1), lambda _: 0, {}) == 1


def test_invalid_entry_scope_and_missing_corrections_fail_closed() -> None:
    original = old.compile_stage(recover()[1].choices[0], 2)
    stage = model.lower(recover()[1].choices[0], original)
    with pytest.raises(ValueError, match="layout"):
        model.evaluate(stage, {})
    for bad in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="uint160"):
            model.evaluate(stage, {s: bad for s in stage.input_slots})
    with pytest.raises(ValueError, match="Boolean"):
        model.catalogue(verify_data=1)
    with pytest.raises(ValueError, match="original field-plane"):
        model.lower(recover()[1].choices[0], replace(original, sites=(), field_kernel_required=True))
