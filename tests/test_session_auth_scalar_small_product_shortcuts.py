"""Remove integer-product thresholds only in the proved small nonzero domain."""

import random
from collections.abc import Callable
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_representative_rules as rules
from tools import scalar_stage_plan as compiler
from tools import transform12_integer_model as exact
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference

P = rules.MODULUS


def missing_lifts(a: int, b: int, lift_a: Callable[[], bool], lift_b: Callable[[], bool]) -> bool:
    return a >= 47 or b >= 47


def test_all_small_lifts_and_large_product_boundaries_match_independent_fold() -> None:
    values = list(range(47)) + list(range(P, P + 47)) + [47, (P + 1) // 2, P - 1]
    for a in values:
        for b in values:
            expected = exact.multiply(a, b)
            if 0 < expected % P <= 46:
                lifted = rules.small_nonzero_product_lift(a % P, b % P, lambda: a >= P, lambda: b >= P)
                assert expected == expected % P + P * lifted


def test_large_factor_skips_both_callbacks_and_small_factors_keep_lazy_or() -> None:
    def unexpected() -> bool:
        raise AssertionError("unnecessary operand lift")

    assert rules.small_nonzero_product_lift(2, (P + 1) // 2, unexpected, unexpected)
    assert rules.small_nonzero_product_lift((P + 1) // 2, 2, unexpected, unexpected)
    assert rules.small_nonzero_product_lift(1, 2, lambda: True, unexpected)
    assert rules.small_nonzero_product_lift(1, 2, lambda: False, lambda: True)
    assert not rules.small_nonzero_product_lift(1, 2, lambda: False, lambda: False)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_every_source_branch_preserves_outputs_and_full_carry_events(cap: int) -> None:
    rng = random.Random(4746320)
    for stage in recover():
        samples = [{s: v for s in stage.inputs} for v in (1, P + 1)]
        samples.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, cap, boolean_corrections=True)
            for state in samples:
                actual = compiler.evaluate(plan, state, stage.index, bit, square_shortcuts=True, small_product_shortcuts=True)
                expected, events = evaluate_stage(stage.index, state, bit)
                assert actual.outputs == expected
                assert actual.defects == events


@pytest.mark.parametrize("point_changing", [False, True])
def test_complete_bytes_and_all_boundaries_preserve_both_lift_cuts(point_changing: bool) -> None:
    if point_changing:
        x, y, selector = (1 << 128) + 48, 917984300236617229462155822449362250189314875415, 0
    else:
        x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
        selector = scalar_xor_mask()
    kwargs = {"boolean_corrections": True, "demand_guards": True, "cofactor_fields": True}
    old, baseline = compiler.full_output(x, y, 0, selector, **kwargs)
    actual, revised = compiler.full_output(x, y, 0, selector, **kwargs, square_shortcuts=True, small_product_shortcuts=True)
    expected = reference(bytes(20), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
    assert actual == old == expected.destination
    assert tuple(r.outputs for r in revised) == tuple(r.outputs for r in baseline)
    assert tuple(r.defects for r in revised) == tuple(r.defects for r in baseline)


def test_eight_actual_ast_obligations_and_missing_lift_mutation() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_small_product_shortcuts import prove

    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 8
    with patch.object(rules, "small_nonzero_product_lift", missing_lifts):
        wrong = prove()
    assert not wrong["full_proof"] and any(row["result"] == "sat" for row in wrong["obligations"])


def test_solver_unknown_and_invalid_timeout_fail_closed() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_small_product_shortcuts import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive solver timeout"):
            prove(timeout)
