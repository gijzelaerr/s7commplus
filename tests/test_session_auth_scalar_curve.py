"""Symbolic scalar recovery, independent controls, and reachable exceptions."""

import random
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform12
from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools import recover_scalar_curve as curve
from tools import recover_scalar_shadow as shadow
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Operand, dispatch_program
from tools.recover_transform12_phase1 import evaluate_stage, recover as stages


def modular_tape(stage_index: int, branch: int, state: dict[int, int]) -> dict[int, int]:
    """Numeric modular interpreter independent of symbolic polynomial operations."""
    program = stages()[stage_index].choices[branch]
    values = {}

    def resolve(operand: Operand) -> int:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return state[operand.index] % shadow.MODULUS
        offset = operand.index * 24
        return exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % shadow.MODULUS

    for instruction in program.instructions:
        a = resolve(instruction.operands[0])
        b = resolve(instruction.operands[-1])
        if instruction.operation in ("multiply", "square"):
            value = a * b
        elif instruction.operation == "add":
            value = a + b
        elif instruction.operation == "subtract":
            value = a - b
        else:
            raise AssertionError("unexpected operation")
        values[instruction.value] = value % shadow.MODULUS
    return {slot: resolve(operand) for slot, operand in program.outputs}


def test_all_320_symbolic_branches_match_independent_modular_interpreter() -> None:
    rng = random.Random(320160)
    for stage in stages():
        state = {slot: rng.getrandbits(160) for slot in stage.inputs}
        inputs = tuple(state[slot] for slot in stage.inputs)
        for bit, program in enumerate(stage.choices):
            formula = shadow.recover(program, stage.inputs)
            actual = {slot: shadow.evaluate(poly, inputs) for slot, poly in formula.outputs.items()}
            assert actual == modular_tape(stage.index, bit, state)


def test_catalogue_is_complete_and_deterministic() -> None:
    report = shadow.catalogue()
    rows = report["branches"]
    assert len(rows) == 320
    assert {(row["stage"], row["branch"]) for row in rows} == {(stage, bit) for stage in range(160) for bit in (0, 1)}
    assert sum(row["instructions"] for row in rows) == 56497
    assert all(len(row["polynomial_sha256"]) == 64 for row in rows)
    assert report == shadow.catalogue()


def test_first_two_stages_are_full_polynomial_identities_without_probes() -> None:
    with patch("tools.recover_transform7_setup.capture_setup", side_effect=AssertionError("no interpolation allowed")):
        assert curve.first_stage() == curve.expected_first_stage()
        assert curve.second_stage() == curve.expected_second_stage()
        assert curve.first_stage_relation()


def test_wrong_curve_constant_breaks_both_stage_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(curve, "CURVE_B", curve.CURVE_B + 1)
    assert curve.first_stage() != curve.expected_first_stage()
    assert curve.second_stage() != curve.expected_second_stage()
    assert not curve.first_stage_relation()


def test_wrong_doubling_coefficient_breaks_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    original = curve.doubling

    def wrong(x: shadow.Polynomial, z: shadow.Polynomial) -> tuple[shadow.Polynomial, shadow.Polynomial]:
        n, d = original(x, z)
        return shadow.add(n, z), d

    monkeypatch.setattr(curve, "doubling", wrong)
    assert curve.first_stage() != curve.expected_first_stage()
    assert curve.second_stage() != curve.expected_second_stage()


def test_differential_relation_is_not_unconditionally_zero() -> None:
    q = curve.differential_relation()
    assert q
    assert shadow.evaluate(q, (1, 1, 1, 1, 0)) != 0


def test_relation_is_preserved_symbolically_by_both_second_stage_branches() -> None:
    rows = curve.second_stage_relation()
    assert len(rows) == 2
    assert all(row["relation_preserved"] and row["remainder_terms"] == 0 for row in rows)
    assert all(row["expanded_relation_terms"] == 760 for row in rows)
    assert all(row["quotient_terms"] == 267 for row in rows)


def test_relation_division_reconstructs_and_detects_nonzero_remainder() -> None:
    x, z, u, v, t = curve.variables(5)
    q = curve.differential_relation()
    factor = shadow.add(curve.product(x, z), curve.product(u, v, t))
    numerator = shadow.multiply(q, factor, 16384)
    quotient, remainder = curve.divide_relation(numerator)
    assert quotient == factor and remainder == {}
    one = {(0, 0, 0, 0, 0): 1}
    corrupted = shadow.add(numerator, one)
    quotient, remainder = curve.divide_relation(corrupted)
    assert remainder == one
    assert shadow.add(shadow.multiply(q, quotient, 16384), remainder) == corrupted


def test_synthetic_reachable_second_stage_carry_disproves_modular_replacement() -> None:
    from tools.recover_transform7_setup import capture_setup

    witness = curve.reachable_counterexample()
    divergence = witness["first_divergence"]
    assert divergence["stage"] == 1
    assert divergence["branch"] == 0
    assert divergence["operation"] == "add"
    assert divergence["operands"] == (exact.LIMIT - 49, (1 << 128) + 48)
    assert divergence["exact_result"] == 140
    assert divergence["shadow_result"] == (1 << 128) + 46
    assert witness["divergent_live_outputs"] == [19, 31]
    initial = curve.setup(witness["source_x"], 0, 0).slots
    assert initial == capture_setup(witness["source_x"], 0, 0)
    state = dict(zip(stages()[0].inputs, initial))
    context = bytearray(transform12.CONTEXT_SIZE)
    for slot, value in state.items():
        context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
    for index in (0, 1):
        program = dispatch_program(index * 2)
        transform12.execute(context, program.start, program.count)
        state = evaluate_stage(stages()[index], state, 0)
        for slot, value in state.items():
            assert bytes(context[slot * 24 : (slot + 1) * 24]) == exact.encode(value)


def test_setup_carry_exception_still_blocks_unconditional_first_stage_formula() -> None:
    from tools.recover_transform7_setup import targeted_base_point_probe

    x, y, r = targeted_base_point_probe()
    assert (y * y - x**3 + x - curve.CURVE_B) % shadow.MODULUS == 0
    initial = curve.setup(x, y, r).slots
    actual = evaluate_stage(stages()[0], dict(zip(stages()[0].inputs, initial)), 0)
    formula = curve.expected_first_stage()[0]
    predicted = {slot: shadow.evaluate(poly, (x, y | 4, r | 4)) for slot, poly in formula.items()}
    assert predicted != {slot: value % shadow.MODULUS for slot, value in actual.items()}


def test_report_pins_sources_and_does_not_claim_runtime_equivalence() -> None:
    report = curve.report()
    assert report["first_stage_matches"] and report["second_stage_matches"]
    assert report["differential_relation_zero_after_either_first_shadow_branch"]
    assert report["discriminant_is_unit"]
    assert report["unmodified_reference_base_point_on_curve"]
    assert report["whole_pipeline_equivalence"] is False
    assert all(row["relation_preserved"] for row in report["second_stage_relation_preservation"])
    assert len(report["source_sha256"]) == 3


@pytest.mark.parametrize("limit", [-1, 0])
def test_recovery_rejects_invalid_term_limits(limit: int) -> None:
    stage = stages()[0]
    with pytest.raises(ValueError, match="positive"):
        shadow.recover(stage.choices[0], stage.inputs, limit)


def test_term_limit_stops_expansion() -> None:
    stage = stages()[0]
    with pytest.raises(ValueError, match="limit"):
        shadow.recover(stage.choices[0], stage.inputs, 1)


def test_substitution_is_symbolic_and_rejects_wrong_input_width() -> None:
    x, y = curve.variables(2)
    polynomial = {(2, 1): 3, (0, 0): 7}
    substituted = shadow.substitute(polynomial, (shadow.add(x, y), y), 2)
    assert substituted == {(2, 1): 3, (1, 2): 6, (0, 3): 3, (0, 0): 7}
    with pytest.raises(ValueError, match="width"):
        shadow.substitute(polynomial, (x,), 2)
    with pytest.raises(ValueError, match="width"):
        shadow.evaluate(polynomial, (1,))
