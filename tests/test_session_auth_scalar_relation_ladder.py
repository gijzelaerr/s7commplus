"""Unconditional, unreduced relation-ladder identities and negative controls."""

import random
from unittest.mock import patch

import pytest

from tools import recover_scalar_curve as curve
from tools import scalar_relation_ladder as model
from tools.recover_scalar_shadow import evaluate, recover
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import evaluate_stage

P = model.P


def test_all_1268_source_coefficient_identities_select_two_variants() -> None:
    report = model.report()
    assert report["unreduced_coordinate_identities"] == 1268
    assert report["compact_variants"] == 2
    assert report["intermediate_relation_on_double"] == tuple(range(1, 16)) + tuple(range(144, 159))
    assert report["final_relation_on_double"] is True
    assert report["whole_runtime_equivalence"] is False


def test_all_318_branches_match_unreduced_source_for_arbitrary_entry_states() -> None:
    rng = random.Random(158144)
    for stage in stages()[1:]:
        samples = [{s: v for s in stage.inputs} for v in (0, 1, 46, 47, P - 1, P, P + 1, P + 46)]
        samples.extend({s: rng.randrange(1 << 160) for s in stage.inputs} for _ in range(3))
        for bit, program in enumerate(stage.choices):
            independent = recover(program, stage.inputs)
            for state in samples:
                expected = {
                    s: evaluate(poly, tuple(state[v] % P for v in stage.inputs)) for s, poly in independent.outputs.items()
                }
                assert model.field_stage(stage.index, state, bit) == expected


def test_actual_numeric_step_and_relation_have_exact_symbolic_coefficients() -> None:
    generic = model.symbolic_step(0, False)
    exceptional = model.symbolic_step(0, True)
    assert generic == curve.doubling(*curve.variables(5)[:2]) + model.symbolic_step(1, False)[:2]
    assert curve.add(exceptional[0], generic[0], -1) == curve.differential_relation()
    assert exceptional[1:] == generic[1:]


def test_q_zero_is_not_silently_assumed_and_dropping_it_changes_outputs() -> None:
    first, second, t = (1, 2), (3, 4), 5
    generic = model.step(first, second, t, 0, False)
    exceptional = model.step(first, second, t, 0, True)
    q = evaluate(curve.differential_relation(), first + second + (t,))
    assert q != 0
    assert (exceptional[0][0] - generic[0][0]) % P == q
    assert exceptional[0][1] == generic[0][1]
    assert exceptional[1] == generic[1]


def test_relation_ladder_does_not_claim_to_replace_compatibility_carries() -> None:
    state = {s: P + 1 for s in stages()[1].inputs}
    exact, events = evaluate_stage(1, state, 0)
    shadow = model.field_stage(1, state, 0)
    assert events
    assert shadow != {s: value % P for s, value in exact.items()}


def test_q_zero_and_incoming_lift_bits_do_not_remove_stage_specific_carries() -> None:
    # Same canonical point, same ladder branch, same phase and all canonical
    # incoming representatives. Different encodings still yield different
    # exact results. Complete Transform7 reachability is not asserted.
    point = (1, 1, 1, 0, 1)
    assert evaluate(curve.differential_relation(), point) == 0
    decoded = []
    counts = []
    for index in (16, 32):
        row = model.recover_all()[index - 1]
        state = {s: evaluate(poly, point) for s, poly in row.inputs.items()}
        assert all(value < P for value in state.values())
        policy = model.policies()[index - 1]
        assert policy.relation_on_double is False
        outputs, events = evaluate_stage(index, state, int(policy.bit_flip))
        slots = tuple(sorted(s for s in outputs if s != 94))
        decoded.append(tuple(evaluate(poly, tuple(outputs[s] % P for s in slots)) for poly in row.decoder))
        counts.append(len(events))
    assert counts == [0, 1]
    assert (decoded[1][0] - decoded[0][0]) % P == 47
    assert decoded[1][1:] == decoded[0][1:]


def test_bad_actual_numerical_formula_fails_source_coefficient_verification() -> None:
    original = model.step

    def wrong(
        first: model.Point, second: model.Point, t: int, bit: int, relation_on_double: bool = False
    ) -> tuple[model.Point, model.Point]:
        a, b = original(first, second, t, bit, relation_on_double)
        return ((a[0] + 1) % P, a[1]), b

    model.policies.cache_clear()
    try:
        with patch.object(model, "step", wrong), pytest.raises(ValueError, match="no unique unconditional"):
            model.policies()
    finally:
        model.policies.cache_clear()


def test_symbolic_execution_rejects_sampled_branches_and_wrong_modulus() -> None:
    value = model.Ring(curve.variables(5)[0])
    with pytest.raises(ValueError, match="sampled branch"):
        bool(value)
    with pytest.raises(ValueError, match="source modulus"):
        value % 17


def test_relation_stage_rejects_wrong_scope_and_layout() -> None:
    for stage in (0, 160, True):
        with pytest.raises(ValueError, match="stage1..159"):
            model.field_stage(stage, {}, 0)
    with pytest.raises(ValueError, match="entry layout"):
        model.field_stage(1, {}, 0)
