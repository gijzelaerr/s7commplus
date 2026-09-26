"""All-wrapper correction accounting and exact, carry-sensitive setup traces."""

from __future__ import annotations

import random
import inspect
from fractions import Fraction
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.recover_monolith6_span_identity import H
from tools.recover_transform7_setup import SLOTS, targeted_base_point_probe
from tools.trace_transform7_setup_corrections import trace, wrapper_correction
from tools.trace_transform7_setup_shadows import NAMES, Expression, compose, conditional_candidate
from tools.transform7_setup_merge import CORRECTION


def test_corrected_dependency_map_and_pair_split_cancellation() -> None:
    expected = {
        46: {0: "1/2", 2: "1", 3: "2", 4: "1", 5: "1"},
        70: {0: "3/4", 1: "1", 2: "1/2", 11: "1/2", 12: "1", 13: "1", 14: "2", 15: "1", 16: "1"},
        48: {
            0: "7/16",
            1: "1",
            2: "3/8",
            3: "1/4",
            6: "1/2",
            9: "1/2",
            10: "1",
            11: "1/4",
            12: "1/2",
            13: "1/2",
            14: "1",
            17: "1",
            18: "2",
            19: "1",
            20: "1",
        },
        94: {21: "1", 22: "1"},
    }
    uncorrected = compose()
    corrected = compose(corrected=True)
    for slot, expression in corrected.items():
        terms = dict(expression.terms)
        assert {name: value for name, value in terms.items() if not name.startswith(("c", "merge"))} == dict(
            uncorrected[slot].terms
        )
        assert {int(name[1:]): value for name, value in terms.items() if name.startswith("c")} == {
            index: Fraction(value) for index, value in expected[slot].items()
        }
        assert {name: value for name, value in terms.items() if name.startswith("merge")} == {f"merge{slot}": Fraction(1)}
        assert not any(name.startswith("split") for name in terms)
    assert not any(name in {"c7", "c8"} for expression in corrected.values() for name, _ in expression.terms)


def test_arbitrary_corrections_follow_independent_call_graph_recurrence() -> None:
    rng = random.Random(0xC011)
    expressions = compose(corrected=True)
    for _ in range(100):
        values = {name: rng.randrange(-P, P) for name in ("X", "Y", "R", "d")}
        values.update((f"c{i}", rng.randrange(-P, P)) for i in range(23))
        values.update((f"merge{slot}", rng.randrange(-P, P)) for slot in SLOTS)
        c = [values[f"c{i}"] for i in range(23)]
        x, y, r, d = (values[name] for name in ("X", "Y", "R", "d"))
        # Independently transcribed pair totals, never inferred from compose().
        p0 = H * d + H * H * r + c[0]
        p1 = H * d + H * H * y + c[1]
        p2 = H * p0 + H * H * x + c[2]
        p3 = H * p2 + H * H * y + c[3]
        out46 = 2 * p3 + c[4] + c[5]
        p6 = H * p3 + H * H * r + c[6]
        # Calls 7 and 8 have no downstream consumers of these four slots.
        p10 = H * (p6 + c[9] + p1) + c[10]
        p12 = H * (p0 + c[11] + p2) + c[12]
        p14 = H * (p12 + c[13] + p1) + c[14]
        out70 = 2 * p14 + c[15] + c[16]
        p18 = H * (p10 + c[17] + p14) + c[18]
        out48 = 2 * p18 + c[19] + c[20]
        out94 = 4 * H * H * x + c[21] + c[22]
        expected = {46: out46, 48: out48, 70: out70, 94: out94}
        assert all(expressions[slot].evaluate(values) == (expected[slot] + values[f"merge{slot}"]) % P for slot in SLOTS)


def test_corrected_composition_on_all_synthetic_setup_contexts() -> None:
    rng = random.Random(0xC7346)
    cases = [(0, 0, 0), (1, 1, 1), ((1 << 160) - 1,) * 3, targeted_base_point_probe()]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(128))
    for case in cases:
        observed = trace(*case)
        assert len(observed.wrappers) == 23
        assert len(observed.merge_corrections) == 4
        assert observed.predicted == observed.actual
        assert all(w.actual == (w.expected_without_correction + w.correction) % P for w in observed.wrappers)
        # Sampling is deliberately not promoted to a universal encoding invariant.
        assert all(w.wrap_balance == w.plain_truncation == 0 for w in observed.wrappers)


def test_carry_witness_is_explained_without_interpolating_candidate() -> None:
    case = targeted_base_point_probe()
    ideal = conditional_candidate().encode(*case)[0]
    with patch("tools.recover_transform7_setup.recover", side_effect=AssertionError("no interpolation allowed")):
        observed = trace(*case)
    assert ideal == 1 << 128
    assert dict(observed.merge_corrections) == {46: CORRECTION, 48: 0, 70: 0, 94: 0}
    assert observed.predicted == observed.actual
    assert observed.predicted[0] == 94 == (ideal + CORRECTION) % P


@pytest.mark.parametrize("name", NAMES)
def test_raw_wrappers_exercise_nonzero_corrections(name: str) -> None:
    rng = random.Random(0xC0FF + NAMES.index(name))
    count = 1 if name == NAMES[1] else 2
    observations = []
    for i in range(64):
        inputs = (rng.randbytes(72), rng.randbytes(72))
        if name != NAMES[1]:
            inputs += (rng.randbytes(24 if name == NAMES[0] else 72),)
        outputs = tuple(bytearray(24 if name == NAMES[2] else 72) for _ in range(count))
        getattr(transform7, name)(*outputs, *inputs)
        value = wrapper_correction(i, name, inputs, tuple(bytes(output) for output in outputs))
        observations.append(value)
        assert value.actual == (value.expected_without_correction + value.correction) % P
        if name == NAMES[0]:
            assert value.correction == 6016 * value.wrap_balance - 12032 * value.plain_truncation
        else:
            assert value.correction == (6016 if name == NAMES[3] else 12032) * value.wrap_balance
    assert any(value.wrap_balance != 0 for value in observations)
    assert any(value.actual != value.expected_without_correction for value in observations)
    if name == NAMES[0]:
        assert all(value.plain_truncation > 0 for value in observations)


def test_expression_evaluation_uses_residues_and_unit_denominators() -> None:
    assert Expression((("x", Fraction(1, 2)),)).evaluate({"x": -2}) == P - 1
    with pytest.raises(KeyError):
        Expression.variable("missing").evaluate({})
    with pytest.raises(ValueError, match="invertible"):
        Expression((("x", Fraction(1, P)),)).evaluate({"x": 1})
    assert MODULUS % P == 12032


def test_wrapper_measurement_rejects_malformed_captures() -> None:
    with pytest.raises(ValueError, match="signature"):
        wrapper_correction(0, "unknown", (), ())
    with pytest.raises(ValueError, match="input length"):
        wrapper_correction(0, NAMES[1], (bytes(71), bytes(72)), (bytes(72),))
    with pytest.raises(ValueError, match="output length"):
        wrapper_correction(0, NAMES[1], (bytes(72), bytes(72)), (bytes(71),))


def test_composition_rejects_merge_of_the_wrong_output_pair() -> None:
    source = inspect.getsource(transform7.execute)
    modified = source.replace("bytes(w[0x18 : 0x18 + 24])", "bytes(w[0x30 : 0x30 + 24])", 1)
    assert source != modified
    with patch("tools.trace_transform7_setup_shadows.inspect.getsource", return_value=modified):
        with pytest.raises(ValueError, match="does not consume"):
            compose(corrected=True)
