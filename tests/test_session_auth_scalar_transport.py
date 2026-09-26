"""Observed error transport, scale homogeneity and representative-tag controls."""

import random
from dataclasses import replace

import pytest

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import recover_scalar_encodings as encoding
from tools import scalar_ladder_model as ladder
from tools import transport_scalar_defects as transport
from tools.recover_scalar_shadow import MODULUS, evaluate, substitute
from tools.recover_transform12_phase1 import evaluate_stage as source_stage
from tools.recover_transform12_phase1 import recover as stages
from tools.trace_scalar_defects import evaluate_stage
from tools.transform7_setup_integer import model as setup


@pytest.fixture(scope="module")
def reference_states():
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    scalar = encoding.scalar_xor_mask()
    state = dict(zip(stages()[0].inputs, setup(x, y, 0).slots))
    result = {}
    for stage in stages():
        bit = scalar >> (159 - stage.index) & 1
        actual, events = evaluate_stage(stage.index, state, bit)
        result[stage.index] = (state, bit, actual, events)
        assert actual == source_stage(stage, state, bit)
        state = actual
    return result


def test_all_entry_decoders_round_trip_reference_boundaries(reference_states) -> None:
    for index in range(1, 160):
        state = reference_states[index][0]
        coordinates = transport.decode_entry(index, state)
        encoder = encoding.initial_encoder() if index == 1 else encoding.recover_all()[index - 2].outputs
        encoded = {slot: evaluate(poly, coordinates + (state[94],)) for slot, poly in encoder.items()}
        assert encoded == {slot: value % MODULUS for slot, value in state.items()}


def test_stage79_independent_errors_cancel_symbolically(reference_states) -> None:
    state, bit, actual, events = reference_states[79]
    assert [e.tape_index for e in events] == [36796, 36808]
    lifted = transport.lift(79, state, bit, events)
    assert all(not any(powers) for poly in lifted.coordinates for powers in poly)
    assert lifted.coordinates[2] == {(0, 0): 47 * (1 << 32)}
    for injected in ((0, 0), (1, 2), (MODULUS - 1, 47)):
        reconstructed = {s: evaluate(poly, injected) for s, poly in lifted.outputs.items()}
        assert reconstructed == {s: value % MODULUS for s, value in actual.items()}
    report = transport.audit(79, state, bit)
    assert report["entry_relation_residue"] == 0
    assert all(point["scale"] == [[0, 0, 1]] for point in report["points"])


def test_stage80_error_is_an_exact_linear_scale(reference_states) -> None:
    state, bit, actual, events = reference_states[80]
    assert [e.tape_index for e in events] == [1092]
    lifted = transport.lift(80, state, bit, events)
    c = 47**4 * (1 << 128)
    assert lifted.coordinates[2] == {(0,): c, (1,): 1}
    assert lifted.coordinates[3] == {}
    report = transport.audit(80, state, bit)
    assert report["zero_defect_baseline_matches_compact_step"]
    assert report["points"][1]["scale"] == [[0, 1], [1, pow(c, -1, MODULUS)]]
    assert report["points"][1]["actual_scale_is_unit"]
    values = tuple(e.correction % MODULUS for e in events)
    assert {s: evaluate(p, values) for s, p in lifted.outputs.items()} == {s: v % MODULUS for s, v in actual.items()}
    # Omitting this event really loses the exact exit, unlike stage79.
    missing = transport.lift(80, state, bit, ())
    assert {s: evaluate(p, ()) for s, p in missing.outputs.items()} != {s: v % MODULUS for s, v in actual.items()}


def test_zero_cross_product_does_not_claim_a_unit_scale() -> None:
    result = transport.projective_correction(({(0,): 1, (1,): 1}, {}))
    assert result["cross_product_identically_zero"] and result["scale_identity"]
    assert evaluate({(0,): 1, (1,): 1}, (MODULUS - 1,)) == 0
    degenerate = transport.projective_correction(({}, {}))
    assert degenerate["baseline_is_zero_vector"] and not degenerate["scale_identity"]
    distorted = transport.projective_correction(({(0,): 1, (1,): 1}, {(0,): 1}))
    assert not distorted["cross_product_identically_zero"] and not distorted["scale_identity"]


def test_real_source_defects_can_change_points_not_only_scale() -> None:
    # Synthetic off-curve witness: do not generalize the reference-point
    # scale identities to arbitrary source inputs.
    state = dict(zip(stages()[0].inputs, setup((1 << 128) + 48, 0, 0).slots))
    state, _ = evaluate_stage(0, state, 0)
    report = transport.audit(1, state, 0)
    assert report["defects"] == [25470, 25476]
    assert report["exit_residues_reconstructed"]
    assert all(not point["cross_product_identically_zero"] and not point["scale_identity"] for point in report["points"])


@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 16, 0x123456789ABCDEF, (1 << 79) - 1, (1 << 159) + 123])
def test_event_assisted_replay_matches_every_boundary_and_exact_tail(n: int) -> None:
    result = transport.reference_case(n)
    replay = result["scale_replay"]
    assert replay["requires_observed_source_defects_and_representative_tags"]
    assert replay["failure"] is None and replay["verified_boundaries"] == 160
    assert replay["tail_with_observed_tags"] == result["tail_actual"]
    closed = replay["closed_suffix_scale"]
    if n < 1 << 79:
        assert closed["conditional_on_verified_observed_defect_schedule"]
        assert closed["matches_scale_replay"]
    if n == 0:
        assert replay["observed_tail_representative_tags"] == (1, 0)
        assert replay["predicted_tail_residues"][0] == 0
        assert result["tail_actual"][0] == MODULUS


def test_homogeneous_scale_recurrence_is_a_full_polynomial_identity() -> None:
    from tools.recover_scalar_curve import scale, variables

    a, b = 17, 23
    variables5 = variables(5)
    scaled = tuple(scale(p, s) for p, s in zip(variables5, (a, a, b, b, 1)))
    for bit, outputs in enumerate(encoding.canonical_outputs()):
        # Degree in each point proves homogeneity for arbitrary scales,
        # not just for the numerical composition control below.
        expected_degrees = ((4, 0), (4, 0), (2, 2), (2, 2)) if bit == 0 else ((2, 2), (2, 2), (0, 4), (0, 4))
        for poly, degrees in zip(outputs, expected_degrees):
            assert all((sum(powers[:2]), sum(powers[2:4])) == degrees for powers in poly)
        next_scales = transport.propagate_scales((a, b), bit)
        assert tuple(substitute(p, scaled, 5) for p in outputs) == tuple(
            scale(p, s) for p, s in zip(outputs, (next_scales[0],) * 2 + (next_scales[1],) * 2)
        )


def test_closed_scale_integer_exponents_match_both_branch_recurrences() -> None:
    rng = random.Random(8079)
    for remaining in (0, 1, 2, 7, 79, 160):
        for n in (0, (1 << remaining) - 1, rng.getrandbits(remaining)):
            a, b = 0, 1
            for index in range(remaining):
                effective_bit = n >> (remaining - index - 1) & 1
                a, b = (4 * a, 2 * a + 2 * b) if effective_bit else (2 * a + 2 * b, 4 * b)
            q = 1 << remaining
            assert (a, b) == (q * (q - n - 1), q * (q - n))
            assert transport.closed_suffix_scale(37, n, remaining) == pow(37, b, MODULUS)


def test_invalid_or_mutated_defect_locations_are_rejected(reference_states) -> None:
    state, bit, _, events = reference_states[80]
    for invalid, match in (
        (events * 9, "eight"),
        (events * 2, "unique"),
        ((replace(events[0], branch=1 - bit),), "match"),
        ((replace(events[0], tape_index=-1),), "outside"),
        ((replace(events[0], operation="multiply"),), "operation"),
    ):
        with pytest.raises(ValueError, match=match):
            transport.lift(80, state, bit, invalid)
    with pytest.raises(ValueError, match="layout"):
        transport.lift(80, {}, bit, events)
    with pytest.raises(ValueError, match="stage index"):
        transport.lift(-1, state, bit, events)
    with pytest.raises(ValueError, match="suffix"):
        transport.closed_suffix_scale(1, 2, 1)
    with pytest.raises(ValueError, match="length"):
        transport.closed_suffix_scale(1, 0, 161)


def test_scale_prediction_is_not_a_claim_of_raw_byte_equivalence() -> None:
    result = transport.reference_case(1)
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    uncorrected = ladder.model(x, y, 0, encoding.scalar_xor_mask() ^ 1)
    assert uncorrected != result["scale_replay"]["predicted_tail_residues"]
    assert "not global predicate recovery or exact-byte rewrite" in result["scope"]
