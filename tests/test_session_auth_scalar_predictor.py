"""Source-polynomial carry prediction, sparse tag rules, and full byte controls."""

import random
from copy import deepcopy
from math import gcd
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import big_int_transforms
from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import predict_scalar_defects as predictor
from tools import recover_scalar_curve as curve
from tools import recover_scalar_relation_terms as relation
from tools import scalar_ladder_model as ladder
from tools import transport_scalar_defects as transport
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as arithmetic
from tools.decompile_transform12 import Instruction, Operand, Program
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_scalar_shadow import evaluate
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference
from tools.transform7_setup_integer import model as setup


def primitive_program(operation: str) -> Program:
    instruction = Instruction(0, 0, 2, operation, (Operand("input", 0), Operand("input", 1)), 0)
    return Program(0, 1, 3, 0, (instruction,), ((2, Operand("value", 0)),))


def test_all_320_source_branches_with_boundary_and_random_layouts() -> None:
    rng = random.Random(32047)
    p = arithmetic.P
    pool = (0, 1, 46, 47, p, p + 1, exact.MASK)
    for stage in stages():
        for bit in (0, 1):
            states = [{s: pool[(k + j) % len(pool)] for j, s in enumerate(stage.inputs)} for k in range(len(pool))]
            states.append({s: rng.getrandbits(160) for s in stage.inputs})
            for state in states:
                result = predictor.predict_stage(stage.index, state, bit)
                actual, events = evaluate_stage(stage.index, state, bit)
                assert result.outputs == actual, (stage.index, bit, state)
                assert result.defects == events, (stage.index, bit, state)
                assert result.representative_operations == 0


@pytest.mark.parametrize("operation", ["add", "subtract", "multiply"])
def test_tag_rules_and_predicted_primitives_match_packed_runtime(operation: str) -> None:
    rng = random.Random(47128)
    p = arithmetic.P
    pool = (0, 1, 2, 45, 46, 47, (1 << 128) - 48, (1 << 128) - 47, p - 2, p - 1, p, p + 1, exact.MASK)
    pairs = [(a, b) for a in pool for b in pool]
    pairs.extend((rng.getrandbits(160), rng.getrandbits(160)) for _ in range(128))
    program = primitive_program(operation)
    native = getattr(
        big_int_transforms,
        {"add": "big_int_addition", "subtract": "big_int_subtraction", "multiply": "big_int_multiplication"}[operation],
    )
    for a, b in pairs:
        result = predictor.predict_program(program, {0: a, 1: b})
        output = bytearray(24)
        native(output, exact.encode(a), exact.encode(b))
        assert exact.encode(result.outputs[2]) == bytes(output), (a, b)
        if operation == "multiply":
            assert exact.encode(predictor.compact_multiply(a, b)) == bytes(output)
        assert result.representative_operations == 0


@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 16, (1 << 79) - 1, (1 << 159) + 123])
def test_predicted_full_output_matches_exact_reference_and_all_boundaries(n: int) -> None:
    source = TRANSFORM7_DATA[0xD8:0x100]
    x, y = (int.from_bytes(source[o : o + 20], "little") for o in (0, 20))
    selector = n ^ scalar_xor_mask()
    output, rows = predictor.full_output(x, y, 0, selector)
    expected = reference(bytes(20), selector.to_bytes(20, "little"), source)
    assert output == expected.destination
    assert rows[159].outputs == dict(zip((5, 87), expected.tail_inputs))
    assert rows[160].outputs == dict(expected.tail_outputs)
    state = dict(zip(stages()[0].inputs, expected.initial))
    for stage, row in zip(stages(), rows):
        state, events = evaluate_stage(stage.index, state, selector >> (159 - stage.index) & 1)
        assert row.outputs == state and row.defects == events
    if n == 0:
        assert [(e.stage, e.tape_index) for row in rows for e in row.defects] == [(79, 36796), (79, 36808), (80, 1092)]
        assert rows[159].outputs[5] == arithmetic.P


def test_arbitrary_synthetic_sources_include_setup_carry_and_small_tags() -> None:
    rng = random.Random(7147)
    p = arithmetic.P
    cases = [(0, 0, 0, 0), (exact.MASK,) * 4, (p, p, p, exact.MASK)]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(4)) for _ in range(6))
    for x, y, r, selector in cases:
        output, rows = predictor.full_output(x, y, r, selector)
        expected = reference(
            r.to_bytes(20, "little"), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little")
        )
        assert output == expected.destination, (x, y, r, selector)
        assert rows[159].outputs == dict(zip((5, 87), expected.tail_inputs))


def test_on_curve_carry_defects_change_the_final_point_not_only_its_scale() -> None:
    # A verified synthetic curve point; no primality assumption is needed
    # to check its equation. This is not a captured PLC public key.
    x = (1 << 128) + 48
    y = 917984300236617229462155822449362250189314875415
    p = arithmetic.P
    assert (y * y - x * x * x + x - curve.CURVE_B) % p == 0
    output, rows = predictor.full_output(x, y, 0, 0)
    assert [(e.stage, e.tape_index) for e in rows[1].defects] == [(1, 25470), (1, 25476)]
    incoming = transport.decode_entry(1, rows[0].outputs)
    outgoing = transport.decode_entry(2, rows[1].outputs)
    assert evaluate(curve.differential_relation(), incoming + (x,)) == 0
    assert evaluate(curve.differential_relation(), outgoing + (x,)) != 0
    z, n = rows[159].outputs[5], rows[159].outputs[87]
    shadow_z, shadow_n = ladder.model(x, y, 0, 0)
    assert gcd(z, p) == gcd(shadow_z, p) == 1
    assert (n * shadow_z - shadow_n * z) % p == 1307426275097508917995851978661085928554276274481
    # Thus no projective rescaling repairs the ordinary ladder here.
    destination = bytearray(72)
    transform7.execute(destination, bytearray(20), bytearray(20), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
    assert output == bytes(destination)


def test_full_output_matches_original_for_all_three_bundled_public_sources() -> None:
    from tools.trace_transform7_tail import cases

    for case in (cases(0)[i] for i in (0, 5, 10)):
        x, y = (int.from_bytes(case.source[o : o + 20], "little") for o in (0, 20))
        output, _ = predictor.full_output(x, y, int.from_bytes(case.prng1, "little"), int.from_bytes(case.prng2, "little"))
        destination = bytearray(72)
        transform7.execute(destination, bytearray(case.prng1), bytearray(case.prng2), case.source)
        assert output == bytes(destination), case.name


def test_no_full_trace_or_primitive_arithmetic_executor_is_called() -> None:
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    with (
        patch.object(exact, "add", side_effect=AssertionError("old integer executor")),
        patch.object(exact, "subtract", side_effect=AssertionError("old integer executor")),
        patch.object(exact, "multiply", side_effect=AssertionError("old integer executor")),
        patch.object(arithmetic, "add", side_effect=AssertionError("old lifted executor")),
        patch.object(arithmetic, "subtract", side_effect=AssertionError("old lifted executor")),
        patch.object(arithmetic, "multiply", side_effect=AssertionError("old lifted executor")),
    ):
        output, rows = predictor.full_output(x, y, 0, scalar_xor_mask())
        assert len(output) == 72
        assert all(row.representative_operations == 0 for row in rows)
        # Exercise positive-small tags too, not only zero tags.
        result = predictor.predict_program(primitive_program("multiply"), {0: arithmetic.P - 1, 1: arithmetic.P - 1})
        assert result.outputs[2] == arithmetic.P + 1 and result.positive_tag_rules == 1


def test_nonlinear_multi_defect_repairs_preserve_cached_templates() -> None:
    state = dict(zip(stages()[0].inputs, setup((1 << 128) + 48, 0, 0).slots))
    state, _ = evaluate_stage(0, state, 0)
    program = stages()[1].choices[0]
    baseline = deepcopy(predictor.program_polynomials(program, stages()[1].inputs))
    result = predictor.predict_stage(1, state, 0)
    actual, events = evaluate_stage(1, state, 0)
    assert result.outputs == actual and result.defects == events
    assert len(result.defects) == 2 and result.repaired_nodes > 2
    assert predictor.program_polynomials(program, stages()[1].inputs) == baseline


def test_false_guard_and_canonical_only_tag_have_observable_negative_controls() -> None:
    program = primitive_program("add")
    state = {0: arithmetic.P - 2, 1: (1 << 128) + 48}
    with patch.object(predictor, "addition_possible", return_value=False):
        assert predictor.predict_program(program, state).outputs[2] != exact.add(*state.values())
    program = primitive_program("multiply")
    state = {0: arithmetic.P - 1, 1: arithmetic.P - 1}
    with patch.object(predictor, "multiplication_lift", return_value=False):
        assert predictor.predict_program(program, state).outputs[2] == 1
        assert exact.multiply(*state.values()) == arithmetic.P + 1


def test_source_ast_guard_and_tag_proofs_with_translation_controls() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import WIDTH, compile_guard, prove

    context = z3.Context()
    p = arithmetic.P
    for value in (0, 46, 47, 92, 93, (1 << 128) + 46, (1 << 128) + 47, p - 1):
        expr = compile_guard(z3, "addition_possible", {"residue": z3.BitVecVal(value, WIDTH, ctx=context)})
        assert z3.is_true(z3.simplify(expr)) == predictor.addition_possible(value)
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 11


def test_generalized_ladder_has_complete_unreduced_source_identities() -> None:
    from tools.recover_scalar_encodings import recover_all

    flags = relation.recover_flags()
    assert flags == tuple(1 <= index <= 15 or 144 <= index <= 159 for index in range(160))
    report = relation.report()
    assert report["unconditional_intermediate_and_final_coordinate_identities"] == 1268
    rng = random.Random(126831)
    for row in recover_all():
        stage = stages()[row.stage]
        coordinates = tuple(rng.getrandbits(160) for _ in range(5))
        assert relation.relation_residue(coordinates[:2], coordinates[2:4], coordinates[4]) == evaluate(
            curve.differential_relation(), coordinates
        )
        for bit, program in enumerate(stage.choices):
            state = {s: evaluate(p, coordinates) for s, p in row.inputs.items()}
            polys = predictor.program_polynomials(program, stage.inputs)
            inputs = tuple(state[s] for s in stage.inputs)
            raw = {s: evaluate(polys[o.index], inputs) if o.kind == "value" else state[o.index] for s, o in program.outputs}
            slots = tuple(s for s in stage.outputs if s != 94)
            decoded = tuple(evaluate(p, tuple(raw[s] for s in slots)) for p in row.decoder)
            first, second = relation.generalized_step(
                coordinates[:2], coordinates[2:4], coordinates[4], bit ^ int(row.bit_flip), flags[row.stage]
            )
            assert decoded == first + second


def test_relation_error_term_matters_after_the_invariant_is_lost() -> None:
    first, second, t = (2, 3), (5, 7), 11
    q = relation.relation_residue(first, second, t)
    assert q != 0
    ordinary = ladder.step(first, second, t, 0)
    corrected = relation.generalized_step(first, second, t, 0, True)
    assert corrected[0] == ((ordinary[0][0] + q) % arithmetic.P, ordinary[0][1])
    assert corrected[1] == ordinary[1]


def test_equal_curve_coordinates_and_Q_do_not_determine_exact_stage_behavior() -> None:
    from tools.recover_scalar_encodings import initial_encoder

    p = arithmetic.P
    t = (1 << 128) + 48
    coordinates = (16, 0, 4 * t, 4, t)
    assert relation.relation_residue(coordinates[:2], coordinates[2:4], t) == 0
    # Synthetic valid stage boundary: infinity and a verified on-curve x.
    # Reachability of BOTH lifts from full Transform7 is not asserted.
    base = {s: evaluate(poly, coordinates) for s, poly in initial_encoder().items()}
    changed = dict(base)
    changed[1] += p
    changed[44] += p
    assert all(0 <= value < exact.LIMIT for value in changed.values())
    assert transport.decode_entry(1, base) == transport.decode_entry(1, changed) == coordinates[:4]
    first = predictor.predict_stage(1, base, 0)
    second = predictor.predict_stage(1, changed, 0)
    a, b = transport.decode_entry(2, first.outputs), transport.decode_entry(2, second.outputs)
    assert (a[2] * b[3] - b[2] * a[3]) % p == 443874032408125879497961245901944481339618099341
    assert any(e.operation == "subtract" and e.correction == 47 for e in second.defects)
    assert first.outputs == evaluate_stage(1, base, 0)[0]
    assert second.outputs == evaluate_stage(1, changed, 0)[0]


def poisoned_guard(residue):
    residue = 0
    return residue >= 0


def test_guard_ast_compiler_rejects_ignored_statements() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import WIDTH, compile_guard

    with patch.object(predictor, "addition_possible", poisoned_guard):
        with pytest.raises(ValueError, match="only a docstring and return"):
            compile_guard(z3, "addition_possible", {"residue": z3.BitVec("residue", WIDTH)})


def test_invalid_domain_and_layout_fail_closed() -> None:
    with pytest.raises(ValueError, match="stage index"):
        predictor.predict_stage(-1, {}, 0)
    with pytest.raises(ValueError, match="layout"):
        predictor.predict_stage(1, {}, 0)
    with pytest.raises(ValueError, match="unsigned 160-bit"):
        predictor.predict(0, 0, 0, -1)
    with pytest.raises(ValueError, match="layout"):
        predictor.predict_program(primitive_program("add"), {0: 1})
