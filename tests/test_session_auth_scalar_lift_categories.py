"""Finite-state lift semantics, exact post-defect conditions and source controls."""

import itertools
import random
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import scalar_lift_categories as categories
from tools import scalar_stage_plan as compiler
from tools import transform12_residue_defects as arithmetic
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.recover_transform12_phase1 import recover
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_reference import model as reference

P = categories.P


def missing_input_lifts(a: int, b: int, defective: bool) -> bool:
    return a == 6 or b == 6


def test_classifier_boundaries_cover_exactly_seven_states() -> None:
    assert [categories.classify(v) for v in (0, P, 1, P + 1, 7, P + 7, 47)] == list(range(7))
    assert categories.classify(6) == 2 and categories.classify(P + 6) == 3
    assert categories.classify(46) == 4 and categories.classify(P + 46) == 5
    assert categories.classify(P - 1) == 6
    for value in (True, -1, 1 << 160):
        with pytest.raises(ValueError, match="unsigned160"):
            categories.classify(value)


def test_finite_states_agree_with_all_independent_primitive_boundary_pairs() -> None:
    boundaries = list(range(47)) + list(range(P, P + 47)) + [47, (1 << 128) - 47, 1 << 128, P - 1]
    for a, b in itertools.product(boundaries, repeat=2):
        sa, sb = categories.classify(a), categories.classify(b)
        for operation in ("add", "subtract", "multiply"):
            exact = getattr(arithmetic, operation)(a, b)
            predicted = categories.transition(operation, exact.residue, sa, sb, bool(exact.correction))
            assert exact.representative == exact.residue + P * predicted
        exact = arithmetic.multiply(a, a)
        assert categories.transition("square", exact.residue, sa, sa) == (exact.representative >= P)


def test_addition_and_nonzero_product_have_the_same_state_transition() -> None:
    for a, b in itertools.product(range(7), repeat=2):
        assert categories.addition_lift(a, b, False) == categories.nonzero_product_lift(a, b)


def test_lazy_category_rules_keep_all_required_input_lifts() -> None:
    def unexpected() -> bool:
        raise AssertionError("unnecessary lift")

    assert categories.small_addition_lift(P - 1, 1, False, unexpected, unexpected)
    assert categories.small_addition_lift(1, 1, False, lambda: True, unexpected)
    assert not categories.small_subtraction_lift(1, P - 1, False, unexpected, unexpected)
    assert categories.small_subtraction_lift(0, 46, True, unexpected, unexpected)
    assert not categories.small_subtraction_lift(1, 1, False, lambda: False, unexpected)


def test_unreachable_defect_outputs_are_rejected_instead_of_certified() -> None:
    for operation, residue in (("add", 0), ("add", 93), ("subtract", 0), ("subtract", 47)):
        with pytest.raises(ValueError, match="inconsistent"):
            categories.transition(operation, residue, 1, 1, True)
    with pytest.raises(ValueError, match="no residue defect"):
        categories.transition("multiply", 1, 1, 1, True)
    with pytest.raises(ValueError, match="0..6"):
        categories.transition("add", 1, 7, 1)


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_all_320_source_branches_use_the_category_rules_exactly(cap: int) -> None:
    rng = random.Random(76320128)
    for stage in recover():
        samples = [{s: v for s in stage.inputs} for v in (1, P, P + 1)]
        samples.append({s: rng.randrange(1 << 160) for s in stage.inputs})
        for bit, source in enumerate(stage.choices):
            plan = compiler.compile_plan(source, cap, boolean_corrections=True)
            for state in samples:
                expected, events = evaluate_stage(stage.index, state, bit)
                actual = compiler.evaluate(plan, state, stage.index, bit, category_lifts=True)
                assert actual.outputs == expected
                assert actual.defects == events


@pytest.mark.parametrize("cap", [2, 8, 64, 256])
def test_complete_reference_bytes_and_all_boundaries_with_categories(cap: int) -> None:
    x, y = (int.from_bytes(TRANSFORM7_DATA[o : o + 20], "little") for o in (0xD8, 0xEC))
    selector = scalar_xor_mask()
    baseline, old = compiler.full_output(x, y, 0, selector, cap, boolean_corrections=True, demand_guards=True)
    actual, new = compiler.full_output(x, y, 0, selector, cap, boolean_corrections=True, demand_guards=True, category_lifts=True)
    expected = reference(bytes(20), selector.to_bytes(20, "little"), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
    assert actual == baseline == expected.destination
    assert tuple(row.outputs for row in new) == tuple(row.outputs for row in old)


def test_category_cofactors_preserve_the_on_curve_point_changing_control() -> None:
    x, y = (1 << 128) + 48, 917984300236617229462155822449362250189314875415
    kwargs = {"boolean_corrections": True, "demand_guards": True, "cofactor_fields": True}
    baseline, old = compiler.full_output(x, y, 0, 0, **kwargs)
    actual, new = compiler.full_output(x, y, 0, 0, **kwargs, category_lifts=True)
    expected = reference(bytes(20), bytes(20), x.to_bytes(20, "little") + y.to_bytes(20, "little"))
    assert actual == baseline == expected.destination
    assert tuple(row.outputs for row in new) == tuple(row.outputs for row in old)
    assert sum(len(row.defects) for row in new) == 30


def test_all_34_actual_category_ast_obligations_and_negative_control() -> None:
    pytest.importorskip("z3")
    from tools.prove_scalar_lift_categories import prove

    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 34
    with patch.object(categories, "addition_lift", missing_input_lifts):
        wrong = prove()
    assert not wrong["full_proof"] and any(row["result"] == "sat" for row in wrong["obligations"])


def test_category_unknown_or_nonpositive_timeout_is_not_proof() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_scalar_lift_categories import prove

    with patch.object(z3.Solver, "check", return_value=z3.unknown):
        assert not prove()["full_proof"]
    for timeout in (0, -1):
        with pytest.raises(ValueError, match="positive solver timeout"):
            prove(timeout)
