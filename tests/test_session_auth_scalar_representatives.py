"""Exact residue/lift normal form: primitive, source-stage, and byte controls."""

import random
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import big_int_transforms, transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import predict_scalar_defects as predictor
from tools import scalar_representative_program as program_rules
from tools import scalar_representative_rules as rules
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as arithmetic
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import evaluate_stage


@pytest.mark.parametrize("operation", ["add", "subtract", "multiply"])
def test_normal_form_matches_packed_primitives_and_independent_oracles(operation: str) -> None:
    p, low = rules.MODULUS, arithmetic.LOW_LIMIT
    pool = (
        0,
        1,
        2,
        23,
        24,
        45,
        46,
        47,
        48,
        92,
        low - 48,
        low - 47,
        low - 1,
        low,
        low + 1,
        low + 46,
        low + 47,
        p - low,
        p - 48,
        p - 47,
        p - 2,
        p - 1,
        p,
        p + 1,
        p + 23,
        p + 24,
        p + 45,
        p + 46,
    )
    rng = random.Random(16047)
    pairs = [(a, b) for a in pool for b in pool]
    pairs.extend((rng.getrandbits(160), rng.getrandbits(160)) for _ in range(256))
    native = getattr(
        big_int_transforms,
        {"add": "big_int_addition", "subtract": "big_int_subtraction", "multiply": "big_int_multiplication"}[operation],
    )
    for a, b in pairs:
        result = getattr(rules, operation)(rules.Representative.from_integer(a), rules.Representative.from_integer(b))
        rep, correction = (result, 0) if operation == "multiply" else result
        actual = getattr(arithmetic, operation)(a, b)
        output = bytearray(24)
        native(output, exact.encode(a), exact.encode(b))
        assert exact.encode(rep.integer()) == bytes(output)
        assert (rep.integer(), rep.residue, correction) == (actual.representative, actual.residue, actual.correction)


def test_every_small_residue_and_lift_pair() -> None:
    for ra in range(47):
        for rb in range(47):
            for ta in (False, True):
                for tb in (False, True):
                    a, b = rules.Representative(ra, ta), rules.Representative(rb, tb)
                    for name in ("add", "subtract"):
                        result, correction = getattr(rules, name)(a, b)
                        actual = getattr(arithmetic, name)(a.integer(), b.integer())
                        assert result.integer() == actual.representative and correction == actual.correction
                    assert rules.multiply(a, b).integer() == exact.multiply(a.integer(), b.integer())


def test_all_source_stages_use_the_standalone_rules_exactly() -> None:
    rng = random.Random(320160)
    pool = (0, 1, 46, arithmetic.P, arithmetic.P + 46, exact.MASK)
    for stage in stages():
        for bit in (0, 1):
            states = [{s: pool[(k + j) % len(pool)] for j, s in enumerate(stage.inputs)} for k in range(len(pool))]
            states.append({s: rng.getrandbits(160) for s in stage.inputs})
            for state in states:
                result = program_rules.execute(stage.choices[bit], state)
                actual, events = evaluate_stage(stage.index, state, bit)
                predicted = predictor.predict_stage(stage.index, state, bit)
                assert result.outputs == actual == predicted.outputs, (stage.index, bit)
                assert result.corrections == tuple(zip(predicted.defect_values, (e.correction for e in events)))


@pytest.mark.parametrize("n", [0, 1, (1 << 79) - 1, (1 << 159) + 123])
def test_full_72_bytes_and_every_boundary_match_source_polynomial_predictor(n: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    selector = n ^ scalar_xor_mask()
    output, rows = program_rules.full_output(x, y, 0, selector)
    predicted, predictions = predictor.full_output(x, y, 0, selector)
    assert output == predicted
    assert [row.outputs for row in rows] == [row.outputs for row in predictions]
    assert [row.corrections for row in rows] == [
        tuple(zip(row.defect_values, (e.correction for e in row.defects))) for row in predictions
    ]


def test_on_curve_point_changing_carries_and_original_packed_full_output() -> None:
    x, y = (1 << 128) + 48, 917984300236617229462155822449362250189314875415
    output, rows = program_rules.full_output(x, y, 0, 0)
    assert len(rows[1].corrections) == 2
    destination = bytearray(72)
    transform7.execute(destination, bytearray(20), bytearray(20), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
    assert output == bytes(destination)


def test_arbitrary_complete_inputs_match_independent_integer_reference() -> None:
    from tools.transform7_reference import model as reference

    rng = random.Random(72160)
    p = arithmetic.P
    cases = [(0, 0, 0, 0), (exact.MASK,) * 4, (p, p, p, exact.MASK)]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(4)) for _ in range(3))
    for x, y, prng1, selector in cases:
        output, rows = program_rules.full_output(x, y, prng1, selector)
        expected = reference(
            prng1.to_bytes(20, "little"), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little")
        )
        assert output == expected.destination
        assert rows[159].outputs == dict(zip((5, 87), expected.tail_inputs))
        assert rows[160].outputs == dict(expected.tail_outputs)


def test_new_rules_never_call_old_primitive_or_polynomial_executors() -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    selector = scalar_xor_mask()
    expected, _ = program_rules.full_output(x, y, 0, selector)
    with (
        patch.object(exact, "add", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "subtract", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "multiply", side_effect=AssertionError("old arithmetic")),
        patch.object(exact, "execute_program", side_effect=AssertionError("old SSA executor")),
        patch.object(arithmetic, "add", side_effect=AssertionError("lifted oracle")),
        patch.object(arithmetic, "subtract", side_effect=AssertionError("lifted oracle")),
        patch.object(arithmetic, "multiply", side_effect=AssertionError("lifted oracle")),
        patch.object(predictor, "predict_program", side_effect=AssertionError("polynomial executor")),
    ):
        assert program_rules.full_output(x, y, 0, selector)[0] == expected


def test_source_ast_smt_rules_and_translation_controls() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_predicate_guards import compile_guard
    from tools.prove_scalar_representative_rules import WIDTH, prove

    ctx = z3.Context()
    sums = (
        0,
        46,
        47,
        92,
        arithmetic.LOW_LIMIT,
        arithmetic.LOW_LIMIT + 46,
        arithmetic.LOW_LIMIT + 47,
        arithmetic.P,
        arithmetic.P + 47,
    )
    for s in sums:
        for k in range(3):
            expressions = {"s": z3.BitVecVal(s, WIDTH, ctx=ctx), "k": z3.BitVecVal(k, WIDTH, ctx=ctx)}
            defect = rules.addition_defect(s, k)
            assert z3.is_true(z3.simplify(compile_guard(z3, "addition_defect", expressions, module=rules))) == defect
            expressions["defective"] = z3.BoolVal(defect, ctx=ctx)
            assert z3.is_true(z3.simplify(compile_guard(z3, "addition_tag", expressions, module=rules))) == rules.addition_tag(
                s, k, defect
            )
    for a, b in ((0, 0), (0, 46), (46, 0), (46, 46), (47, 46)):
        for ta in (False, True):
            for tb in (False, True):
                expressions = {
                    "a": z3.BitVecVal(a, WIDTH, ctx=ctx),
                    "b": z3.BitVecVal(b, WIDTH, ctx=ctx),
                    "ta": z3.BoolVal(ta, ctx=ctx),
                    "tb": z3.BoolVal(tb, ctx=ctx),
                }
                for name in ("subtraction_defect", "subtraction_tag"):
                    expr = compile_guard(z3, name, expressions, module=rules)
                    assert z3.is_true(z3.simplify(expr)) == getattr(rules, name)(a, b, ta, tb)
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 9


def test_dropping_lift_bits_and_disabling_corrections_are_negative_controls() -> None:
    p = rules.MODULUS
    a, b = rules.Representative(0), rules.Representative(46, True)
    result, correction = rules.subtract(a, b)
    assert correction == 47 and result.integer() == p + 1
    assert rules.subtract(a, rules.Representative(46))[0].integer() != result.integer()
    a, b = rules.Representative.from_integer(p - 2), rules.Representative.from_integer((1 << 128) + 48)
    correct, correction = rules.add(a, b)
    assert correction == arithmetic.ADD_DEFECT
    with patch.object(rules, "addition_defect", return_value=False):
        assert rules.add(a, b)[0].integer() != correct.integer()


@pytest.mark.parametrize("residue,lifted", [(-1, False), (arithmetic.P, False), (47, True), (0, 1), (True, False)])
def test_invalid_residue_lift_domain_fails_closed(residue: int, lifted: bool) -> None:
    with pytest.raises(ValueError):
        rules.Representative(residue, lifted)


def test_invalid_program_inputs_and_unknown_operations_fail_closed() -> None:
    from tools.decompile_transform12 import Instruction, Operand, Program

    instruction = Instruction(0, 0, 2, "unsupported", (Operand("input", 0), Operand("input", 1)), 0)
    program = Program(0, 1, 3, 0, (instruction,), ((2, Operand("value", 0)),))
    with pytest.raises(ValueError, match="layout"):
        program_rules.execute(program, {0: 1})
    with pytest.raises(ValueError, match="unsupported"):
        program_rules.execute(program, {0: 1, 1: 2})
    for value in (-1, 1 << 160, True):
        with pytest.raises(ValueError):
            rules.Representative.from_integer(value)
