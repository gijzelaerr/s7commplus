"""Source-derived packing/merge equations, exhaustive carry windows, and actual setup."""

import random

import pytest

from s7commplus.session_auth.family0 import big_int_operations, big_int_transforms
from tools import transform7_setup_merge as model
from tools.recover_transform7_setup import recover, targeted_base_point_probe


def _runtime_merge(first: int, second: int) -> bytes:
    output = bytearray(24)
    big_int_transforms.big_int_addition(output, model.encode_payload(first), model.encode_payload(second))
    return bytes(output)


def test_prepare_all_high_bytes_and_fold_boundaries() -> None:
    mask = model.arithmetic.MASK
    p = model.arithmetic.CANDIDATE_MODULUS
    for high in range(256):
        lows = [0, 1, 46, 47, mask, p - 1, p, mask - high * 47, mask - high * 47 + 1]
        for low in lows:
            if not 0 <= low <= mask:
                continue
            payload = (high << 160) | low
            packed = model.encode_payload(payload)
            prepared = bytearray(20)
            big_int_operations.prepare(prepared, packed)
            actual = model.prepare_payload(payload)
            assert actual == int.from_bytes(prepared, "little")
            assert 0 <= actual < model.arithmetic.LIMIT
            assert actual % p == payload % p
            assert model.decode_payload(packed) == payload


def test_all_47_lost_carry_remainders_and_threshold_neighbors() -> None:
    for high in [0, 1, 1 << 31, (1 << 32) - 1]:
        for offset in range(-2, 47):
            low = model.LOW_LIMIT - 47 + offset
            total = model.arithmetic.LIMIT + high * model.LOW_LIMIT + low
            if total > 2 * model.arithmetic.MASK:
                continue
            first, second = model.arithmetic.MASK, total - model.arithmetic.MASK
            merged = model.merge(first, second)
            assert merged.total == total
            assert merged.lost_carry == (offset >= 0)
            assert model.arithmetic.encode(merged.result) == _runtime_merge(first, second)
            assert (
                merged.result % model.arithmetic.CANDIDATE_MODULUS
                == (merged.ideal_residue + merged.residue_correction) % model.arithmetic.CANDIDATE_MODULUS
            )
    # The low-128 carry condition alone is insufficient without 160-bit overflow.
    merged = model.merge(model.LOW_MASK, 0)
    assert not merged.lost_carry
    assert merged.result == model.LOW_MASK


def test_seeded_168_bit_operands_and_noncanonical_field_representatives() -> None:
    rng = random.Random(16847)
    p = model.arithmetic.CANDIDATE_MODULUS
    pairs = [(0, 0), (p, 0), (model.PAYLOAD_LIMIT - 1, model.PAYLOAD_LIMIT - 1)]
    pairs.extend((rng.getrandbits(168), rng.getrandbits(168)) for _ in range(2000))
    for first, second in pairs:
        merged = model.merge(first, second)
        assert model.arithmetic.encode(merged.result) == _runtime_merge(first, second)
        assert merged.result % p == (merged.ideal_residue + merged.residue_correction) % p
    assert model.merge(p, 0).result == p  # Exact bytes need not be canonical residues.


def test_real_setup_merges_explain_the_reachable_affine_exception() -> None:
    inputs = targeted_base_point_probe()
    candidate = dict(zip((46, 48, 70), recover().encode(*inputs)))
    candidate[94] = inputs[0]
    observed = dict(model.capture_merges(*inputs))
    assert set(observed) == {46, 48, 70, 94}
    for slot, merged in observed.items():
        assert merged.ideal_residue == candidate[slot]
        assert merged.lost_carry == (slot == 46)
    witness = observed[46]
    assert witness.total == model.arithmetic.LIMIT + model.LOW_LIMIT - 47
    assert witness.ideal_residue == model.LOW_LIMIT
    assert witness.result == 94
    assert witness.result == (witness.ideal_residue + model.CORRECTION) % model.arithmetic.CANDIDATE_MODULUS


def test_real_setup_on_independent_random_inputs() -> None:
    rng = random.Random(0x717)
    candidate = recover()
    for _ in range(64):
        inputs = (rng.getrandbits(160), rng.getrandbits(160), rng.getrandbits(160))
        predicted = dict(zip((46, 48, 70), candidate.encode(*inputs)))
        predicted[94] = inputs[0] % model.arithmetic.CANDIDATE_MODULUS
        for slot, merged in model.capture_merges(*inputs):
            # Capture itself checks all four exact output byte strings.
            assert merged.ideal_residue == predicted[slot]


def test_same_modular_sum_does_not_determine_the_compatibility_result() -> None:
    clean = model.merge(model.LOW_LIMIT, 0)
    exceptional = model.merge(model.arithmetic.MASK, model.LOW_LIMIT - 46)
    assert clean.ideal_residue == exceptional.ideal_residue == model.LOW_LIMIT
    assert not clean.lost_carry and exceptional.lost_carry
    assert clean.result == model.LOW_LIMIT
    assert exceptional.result == 94


@pytest.mark.parametrize("packed", [b"", bytes(23), b"\x01" + bytes(23), bytes(23) + b"\x80"])
def test_invalid_lane_packing_rejected(packed: bytes) -> None:
    with pytest.raises(ValueError):
        model.decode_payload(packed)


@pytest.mark.parametrize("payload", [-1, model.PAYLOAD_LIMIT])
def test_out_of_range_payloads_rejected(payload: int) -> None:
    with pytest.raises(ValueError):
        model.encode_payload(payload)
    with pytest.raises(ValueError):
        model.prepare_payload(payload)
