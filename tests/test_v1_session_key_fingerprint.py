"""The fingerprint SPN matches the answers of HarpoS7's gate network and the direct port it replaced."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from s7commplus.v1_session_key.real_plc import fingerprint

# Recorded from the retired HarpoS7 port, which also agreed with its gate network on every challenge.
_VECTORS = json.loads((Path(__file__).parent / "fixtures/family0/reference_vectors.json").read_text(encoding="utf-8"))


def _fingerprint(challenge: bytes) -> bytes:
    output = bytearray(8)
    fingerprint.fingerprint_challenge(output, challenge)
    return bytes(output)


@pytest.mark.parametrize("vector", _VECTORS["fingerprint"], ids=lambda vector: vector["challenge"])
def test_matches_the_recorded_harpo_answers(vector: dict[str, str]) -> None:
    """Random, constant and single-nibble challenges, with the answers HarpoS7's port and gate network gave."""
    assert _fingerprint(bytes.fromhex(vector["challenge"])) == bytes.fromhex(vector["fingerprint"])


def test_output_ignores_the_destination_contents() -> None:
    challenge = bytes.fromhex(_VECTORS["fingerprint"][0]["challenge"])
    output = bytearray(random.Random(4600).randbytes(8))
    fingerprint.fingerprint_challenge(output, challenge)
    assert bytes(output) == _fingerprint(challenge)


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
