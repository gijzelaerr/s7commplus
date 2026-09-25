"""Caller-level controls: raw differences may disappear or survive SeedTransform."""

import hashlib
import os
from dataclasses import replace
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import pre_seed_transform, seed_transform, transform7
from s7commplus.session_auth.family0._generated import monolith1
from s7commplus.session_auth.keys import KeyFamily
from s7commplus.session_auth.legacy_auth import authenticate_real_plc
from tools import trace_scalar_seed_boundary as boundary
from tools import transform12_integer_model as arithmetic
from tools import transform7_reference as reference_module
from tools.recover_scalar_curve import CURVE_B
from tools.recover_scalar_encodings import recover_all
from tools.recover_scalar_shadow import MODULUS as P
from tools.recover_transform12_phase1 import recover as stages
from tools.recover_transform7_setup import capture_setup, recover as affine_setup
from tools.scalar_stage_plan import constant
from tools.transform7_setup_integer import model as setup


@pytest.mark.parametrize("case", boundary.cases(), ids=lambda case: case.name)
def test_first_nonce_acceptance_and_all_60_bytes_against_original(case: boundary.Case) -> None:
    original = boundary.first_nonce(case, "original")
    exact = boundary.first_nonce(case, "reference")
    candidate = boundary.first_nonce(case, "modular")
    assert original == exact  # Includes raw bytes, loop counts and retry behavior.
    assert candidate.accepted == original.accepted
    assert candidate.entropy_requests == original.entropy_requests
    if case.name in ("synthetic-on-curve-carry", "vendored-key-scalar-carry"):
        assert original.accepted and original.seed is not None and candidate.seed is not None
        assert original.seed[:20] != candidate.seed[:20]
        assert original.seed[20:] == candidate.seed[20:]
    else:
        assert candidate.seed == original.seed
    if case.name == "synthetic-on-curve-carry":
        assert original.seed is not None and candidate.seed is not None
        assert hashlib.sha256(original.seed).hexdigest() == "9c62cab2361d9df3ee4a7d8a5a6ad6678fb7222d2d3686adb800e241b97ededa"
        assert hashlib.sha256(candidate.seed).hexdigest() == "adb13bee1d95ddc34cdf178750d1a01057cdaaff57fa208ff6c3e01610f152e5"
        assert original.normalization_iterations == (2, 1)
        assert candidate.normalization_iterations == (2, 2)
        x, y = (int.from_bytes(case.public_key[offset : offset + 20], "little") for offset in (0, 20))
        assert (y * y - x**3 + x - CURVE_B) % P == 0
    if case.name == "vendored-key-scalar-carry":
        assert original.seed is not None and candidate.seed is not None
        assert hashlib.sha256(original.seed).hexdigest() == "dc1fe5f0d18e7f7af671c39b597f2fe2b02907a82b28a64047c1829d454dc655"
        assert hashlib.sha256(candidate.seed).hexdigest() == "effb442f73d880a6233309bb7f35c1ceb6ed84989a7ec766f835e5991de8e300"
        assert original.normalization_iterations == (2, 2)
        assert candidate.normalization_iterations == (2, 1)
    if case.name == "vendored-key-setup-carry":
        x, y = (int.from_bytes(case.public_key[offset : offset + 20], "little") for offset in (0, 20))
        assert dict(setup(x, y, case.prng1).merges)[46].lost_carry
        assert original.transform_outputs[0] == candidate.transform_outputs[0]
        assert original.transform_outputs[1] != candidate.transform_outputs[1]
        assert original.accepted  # A real raw difference, erased by the caller.
    if case.name == "public-generator-zero-scalar":
        assert not original.accepted and original.seed is None
        assert len(original.transform_outputs) == 1
        assert original.entropy_requests == 3  # Observed retry, not a fabricated success.


def test_caller_difference_is_not_specific_to_zero_transform1() -> None:
    case = replace(boundary.cases()[2], transform1=bytes(range(60)))
    original = boundary.first_nonce(case, "original")
    exact = boundary.first_nonce(case, "reference")
    candidate = boundary.first_nonce(case, "modular")
    assert original == exact
    assert original.accepted and candidate.accepted
    assert original.seed is not None and candidate.seed is not None
    assert original.seed[:20] != candidate.seed[:20]
    assert original.seed[20:] == candidate.seed[20:]


def test_bundled_key_difference_survives_actual_preseed_transform() -> None:
    transform1 = bytearray(60)
    pre_seed_transform.execute(transform1, bytes(range(24)))
    case = replace(boundary.cases()[4], transform1=bytes(transform1))
    original = boundary.first_nonce(case, "original")
    exact = boundary.first_nonce(case, "reference")
    candidate = boundary.first_nonce(case, "modular")
    assert original == exact and original.accepted and candidate.accepted
    assert original.seed is not None and candidate.seed is not None
    assert original.seed[:20] != candidate.seed[:20]
    assert original.seed[20:] == candidate.seed[20:]
    assert hashlib.sha256(original.seed).hexdigest() == "f1c44e2fbf2c8271d45f05e5690ebade88692c7380c9af438fcedfebd79bcc8a"
    assert hashlib.sha256(candidate.seed).hexdigest() == "55d4fe6a138671c909403571138d5fbef3a28581fb0c84facf558f22e0190ba2"


def test_bundled_key_carry_changes_the_complete_180_byte_authentication_blob() -> None:
    case = boundary.cases()[4]
    recover_all()
    reference_module.tail_program()
    original_transform = transform7.execute
    entropy = (bytes(range(24, 48)), bytes(range(24)), bytes(range(16)), case.prng1.to_bytes(20, "little"), bytes(20))

    def run(implementation: boundary.Implementation) -> tuple[bytes, bytes]:
        requests = 0

        def fixed_entropy(length: int) -> bytes:
            nonlocal requests
            assert requests < len(entropy), "unexpected retry or extra entropy request"
            value = entropy[requests]
            requests += 1
            assert length == len(value)
            return value

        def normalize(buffer: bytearray) -> None:
            for _ in range(32):
                if monolith1.execute(buffer, bytes(buffer[:72])):
                    return
            raise AssertionError("synthetic normalization exceeded its bound")

        def scalar(destination: bytearray, prng1: bytearray, selector: bytearray, source: bytes) -> None:
            if implementation == "original":
                original_transform(destination, prng1, selector, source)
            elif implementation == "reference":
                destination[:72] = reference_module.model(bytes(prng1), bytes(selector), source).destination
            else:
                destination[:72] = boundary.modular_output(bytes(prng1), bytes(selector), source)

        with (
            patch.object(os, "urandom", fixed_entropy),
            patch.object(seed_transform, "_monolith1_loop", normalize),
            patch.object(transform7, "execute", scalar),
        ):
            result = authenticate_real_plc(bytes(range(20)), case.public_key, KeyFamily.S7_1500)
        assert requests == 5
        return result

    original_blob, original_key = run("original")
    reference_blob, reference_key = run("reference")
    candidate_blob, candidate_key = run("modular")
    assert len(original_blob) == len(candidate_blob) == 180
    assert len(original_key) == len(candidate_key) == 24
    assert (original_blob, original_key) == (reference_blob, reference_key)
    assert candidate_key == original_key
    assert candidate_blob[:48] == original_blob[:48]  # Metadata.
    assert candidate_blob[48:68] != original_blob[48:68]  # Observable encrypted seed.
    assert candidate_blob[68:] == original_blob[68:]


def test_bundled_key_counterexample_is_constructed_at_the_first_scalar_carry() -> None:
    case = boundary.cases()[4]
    x, y = (int.from_bytes(case.public_key[offset : offset + 20], "little") for offset in (0, 20))
    first = stages()[0].choices[0].instructions[0]
    assert first.operation == "add" and first.tape_index == 30506
    assert first.operands[0].kind == "constant"
    assert first.operands[1].kind == "input" and first.operands[1].index == 70
    literal = constant(first.operands[0])
    candidate = affine_setup()
    a, b, c = candidate.matrix[2]
    constructed = ((1 << 128) - literal - candidate.offsets[2] - a * x - b * (y | 4)) * pow(c, -1, P) % P
    assert constructed == case.prng1 and constructed & 4
    exact_setup = setup(x, y, case.prng1)
    assert not any(merge.lost_carry for _, merge in exact_setup.merges)
    assert capture_setup(x, y, case.prng1) == exact_setup.slots
    input70 = dict(exact_setup.merges)[70].result
    assert literal + input70 == P + (1 << 128)
    assert arithmetic.add(literal, input70) == 94
    assert (literal + input70) % P == 1 << 128  # Dropping the correction changes the field, not just its lift.


def test_normalization_bound_fails_closed_and_restores_patches() -> None:
    original_transform, original_loop = transform7.execute, seed_transform._monolith1_loop
    with patch.object(monolith1, "execute", return_value=0) as normalized:
        with pytest.raises(ValueError, match="declared bound"):
            boundary.first_nonce(boundary.cases()[1], "original", normalization_limit=2)
        assert normalized.call_count == 2
    assert transform7.execute is original_transform
    assert seed_transform._monolith1_loop is original_loop


def test_inputs_and_candidate_domain_are_explicit() -> None:
    valid = boundary.cases()[0]
    for fields in ({"public_key": bytes(39)}, {"transform1": bytes(61)}, {"prng1": True}, {"selector": 1 << 160}):
        with pytest.raises(ValueError):
            replace(valid, **fields)
    for limit in (True, 0, 33):
        with pytest.raises(ValueError, match="normalization limit"):
            boundary.first_nonce(valid, "original", limit)
    with pytest.raises(ValueError, match="unknown diagnostic"):
        boundary.first_nonce(valid, "unknown")  # type: ignore[arg-type]
    for entropy, selector, key in ((bytes(19), bytes(20), bytes(40)), (bytes(20), bytes(20), bytes(39))):
        with pytest.raises(ValueError, match="candidate needs"):
            boundary.modular_output(entropy, selector, key)
