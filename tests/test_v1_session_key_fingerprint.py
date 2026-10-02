"""The fingerprint SPN matches HarpoS7's gate network and the direct port it replaced."""

from __future__ import annotations

import random

import pytest

from s7commplus.v1_session_key.real_plc import fingerprint
from old.family0 import fingerprint as harpo
from tools import recover_fingerprint


def _fingerprint(challenge: bytes) -> bytes:
    output = bytearray(8)
    fingerprint.fingerprint_challenge(output, challenge)
    return bytes(output)


def _reference(challenge: bytes, destination: bytes = bytes(8)) -> bytes:
    output = bytearray(destination)
    harpo.harpo_fingerprint(output, challenge)
    return bytes(output)


def test_constants_are_recovered_from_the_gate_network() -> None:
    recovered = recover_fingerprint.recover(harpo.gates())
    assert recovered.input_key == fingerprint.INPUT_KEY
    assert recovered.round_keys == list(fingerprint.ROUND_KEYS)
    assert recovered.round_wiring == [list(wiring) for wiring in fingerprint.ROUND_WIRING]
    assert recovered.output == list(fingerprint.OUTPUT_CRUMBS)
    assert recovered.output_encoding == list(fingerprint.OUTPUT_ENCODING)


def test_inverse_sbox_is_aes() -> None:
    assert list(fingerprint.INV_SBOX) == recover_fingerprint.inv_sbox_table()


def test_matches_the_gate_network_on_random_challenges() -> None:
    network = harpo.gates()
    rng = random.Random(4603)
    for _ in range(300):
        challenge = rng.randbytes(18)
        assert _fingerprint(challenge) == harpo.evaluate(network, challenge)


def test_matches_the_harpo_port_on_random_challenges() -> None:
    rng = random.Random(4600)
    for _ in range(300):
        challenge = rng.randbytes(20)
        # The port's output ignores the destination's previous contents too.
        assert _fingerprint(challenge) == _reference(challenge, rng.randbytes(8))


@pytest.mark.parametrize("fill", [0x00, 0x0F, 0xF0, 0xFF])
def test_matches_the_harpo_port_on_constant_challenges(fill: int) -> None:
    assert _fingerprint(bytes([fill]) * 18) == _reference(bytes([fill]) * 18)


def test_matches_the_harpo_port_on_single_nibble_changes() -> None:
    base = bytes(18)
    for nibble in range(32):
        for value in (1, 8, 15):
            challenge = bytearray(base)
            challenge[2 + nibble // 2] = value << 4 if nibble % 2 == 0 else value
            assert _fingerprint(bytes(challenge)) == _reference(bytes(challenge))


def test_only_challenge_bytes_2_to_18_are_used() -> None:
    rng = random.Random(4601)
    challenge = rng.randbytes(20)
    variant = rng.randbytes(2) + challenge[2:18] + rng.randbytes(4)
    assert _fingerprint(challenge) == _fingerprint(variant)


def test_each_round_transposes_crumbs_within_two_groups_of_four_bytes() -> None:
    for wiring in fingerprint.ROUND_WIRING:
        groups = {sources for _, sources in wiring}
        assert len(groups) == 2
        assert sorted(byte for sources in groups for byte in sources) == list(range(8))
        for group in groups:
            assert sorted(j for j, sources in wiring if sources == group) == [0, 1, 2, 3]


def test_output_reads_every_crumb_of_the_final_state_once() -> None:
    read = sorted((j, byte) for j, a, b in fingerprint.OUTPUT_CRUMBS for byte in (a, b))
    assert read == [(j, byte) for j in range(4) for byte in range(8)]
    assert all(sorted(table) == list(range(16)) for table in fingerprint.OUTPUT_ENCODING)


def test_rejects_short_buffers() -> None:
    with pytest.raises(ValueError, match="destination"):
        fingerprint.fingerprint_challenge(bytearray(7), bytes(18))
    with pytest.raises(ValueError, match="challenge"):
        fingerprint.fingerprint_challenge(bytearray(8), bytes(17))
