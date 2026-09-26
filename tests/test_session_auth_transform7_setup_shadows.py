"""Candidate wrapper identities, conditional AST composition, and limits."""

from __future__ import annotations

import random
from collections import Counter
from fractions import Fraction
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.recover_transform7_setup import capture_setup, recover, targeted_base_point_probe
from tools.trace_transform7_setup_shadows import compose, conditional_candidate, span_shadow, trace


def test_conditional_composition_cancels_unknown_pair_splits() -> None:
    expected = {
        46: {"d": Fraction(1, 4), "X": Fraction(1, 4), "Y": Fraction(1, 2), "R": Fraction(1, 8)},
        48: {"d": Fraction(23, 32), "X": Fraction(3, 32), "Y": Fraction(5, 16), "R": Fraction(15, 64)},
        70: {"d": Fraction(7, 8), "X": Fraction(1, 8), "Y": Fraction(1, 4), "R": Fraction(3, 16)},
        94: {"X": Fraction(1)},
    }
    assert {slot: dict(expression.terms) for slot, expression in compose().items()} == expected


def test_offsets_come_from_data_without_interpolation() -> None:
    with patch("tools.recover_transform7_setup.capture_setup", side_effect=AssertionError("no probes allowed")):
        candidate = conditional_candidate()
    assert span_shadow(TRANSFORM7_DATA[:72]) == 0
    assert span_shadow(TRANSFORM7_DATA[72:144]) == 479351431067838523670377406553314858552643643568
    assert candidate == recover()


def test_wrapper_hypotheses_on_structured_and_random_setup_calls() -> None:
    rng = random.Random(0x7346)
    cases = [(0, 0, 0), (1, 1, 1), ((1 << 160) - 1,) * 3, targeted_base_point_probe()]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(128))
    for case in cases:
        observations = trace(*case)
        assert Counter(value.operation for value in observations) == {
            "monolith3_with_copy": 6,
            "monolith4_with_copy": 8,
            "monolith5_with_copy": 4,
            "monolith6_with_copy": 5,
        }
        assert all(value.actual == value.expected for value in observations)


def test_conditional_candidate_still_requires_merge_correction() -> None:
    case = targeted_base_point_probe()
    assert conditional_candidate().encode(*case)[0] == 1 << 128
    assert capture_setup(*case)[0] == 94
    assert all(value.actual == value.expected for value in trace(*case))


def test_wrapper_hypothesis_is_not_valid_for_arbitrary_encoded_bytes() -> None:
    rng = random.Random(0xBAD4)
    deltas = []
    for _ in range(2):
        left, right = rng.randbytes(72), rng.randbytes(72)
        output = bytearray(72)
        transform7.monolith4_with_copy(output, left, right)
        deltas.append((span_shadow(bytes(output)) - span_shadow(left) - span_shadow(right)) % P)
    # A negative control: any proof needs a valid-input encoding invariant.
    assert deltas == [0, -MODULUS % P]


def test_span_shadow_validates_length() -> None:
    with pytest.raises(ValueError, match="72 bytes"):
        span_shadow(bytes(71))
