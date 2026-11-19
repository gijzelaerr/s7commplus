"""``present`` and ``seed`` match the published PRESENT vectors, the HarpoS7 ports' recorded answers and upstream vectors."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest

from s7commplus.v1_session_key.handshake import authenticate_real_plc
from s7commplus.v1_session_key.keys import KeyFamily, get_public_key
from s7commplus.v1_session_key.real_plc import present, seed

_FIXTURES = Path(__file__).parent / "fixtures" / "family0"
_TRANSFORMS = _FIXTURES / "transforms"
# Recorded from the retired HarpoS7 ports (PreSeed-, KeyDerivation-, Transform13 and the encoded
# authentication chain) before they moved to the s7commplus-research repository.
_VECTORS = json.loads((_FIXTURES / "reference_vectors.json").read_text(encoding="utf-8"))
_UPSTREAM = _VECTORS["upstream_decoded"]


def _derived_bytes(pre_seed: int) -> bytes:
    keys = seed.derive_keys(pre_seed)
    return keys.challenge_key + keys.checksum_key + keys.hash_key.to_bytes(16, "little")


def _standard_round_keys(key: int) -> list[int]:
    keys = []
    for counter in range(1, 33):
        keys.append(key >> 16)
        key = ((key << 61) | (key >> 19)) & ((1 << 80) - 1)
        key = (present.SBOX[key >> 76] << 76) | (key & ((1 << 76) - 1))
        key ^= counter << 15
    return keys


@pytest.mark.parametrize(
    ("plaintext", "key", "ciphertext"),
    [
        (0, 0, 0x5579C1387B228445),
        (0, (1 << 80) - 1, 0xE72C46C0F5945049),
        ((1 << 64) - 1, 0, 0xA112FFC72F68417B),
        ((1 << 64) - 1, (1 << 80) - 1, 0x3333DCD3213210D2),
    ],
)
def test_rounds_reproduce_the_published_present80_vectors(plaintext: int, key: int, ciphertext: int) -> None:
    assert present.present_rounds(plaintext, _standard_round_keys(key)) == ciphertext


@pytest.mark.parametrize("vector", _VECTORS["seed_mask"], ids=lambda vector: vector["shared_x"][:8])
def test_seed_mask_matches_transform13(vector: dict[str, str]) -> None:
    assert seed.seed_mask(int(vector["shared_x"], 16)) == int(vector["seed_mask"], 16)


def test_transform13_upstream_vector() -> None:
    assert seed.seed_mask(int(_UPSTREAM["transform13-src"], 16)) == int(_UPSTREAM["transform13-dst"], 16)


@pytest.mark.parametrize("vector", _VECTORS["pre_seed"], ids=lambda vector: vector["key1"][:8])
def test_pre_seed_value_matches_the_handwritten_port(vector: dict[str, str]) -> None:
    assert seed.pre_seed(bytes.fromhex(vector["key1"])) == int(vector["pre_seed"], 16)


def test_pre_seed_upstream_vector() -> None:
    source = (_TRANSFORMS / "transform1-src.bin").read_bytes()
    assert seed.pre_seed(source) == int(_UPSTREAM["transform1-dst"], 16)


def test_pre_seed_value_rejects_short_sources() -> None:
    with pytest.raises(ValueError, match="key1 too small"):
        seed.pre_seed(bytes(23))


@pytest.mark.parametrize("vector", _VECTORS["key_derivation"], ids=lambda vector: vector["pre_seed"][:8])
def test_key_derivation_value_matches_the_handwritten_port(vector: dict[str, str]) -> None:
    assert _derived_bytes(int(vector["pre_seed"], 16)) == bytes.fromhex(vector["derived"])


def test_key_derivation_upstream_vector() -> None:
    expected = (_TRANSFORMS / "transform2-dst.bin").read_bytes()
    assert _derived_bytes(int(_UPSTREAM["transform2-src"], 16)) == expected


def _replay(entropy: list[str]) -> Iterator[bytes]:
    yield from (bytes.fromhex(value) for value in entropy)


@pytest.mark.parametrize("vector", _VECTORS["authentication"], ids=lambda vector: f"{vector['family']}-{vector['challenge'][:8]}")
def test_authentication_matches_the_encoded_transform_chain(vector: dict[str, object]) -> None:
    """The blob and session key the HarpoS7 ports' encoded chain gave for the same challenge and entropy."""
    entropy = _replay(vector["entropy"])  # type: ignore[arg-type]

    def urandom(length: int) -> bytes:
        value = next(entropy)
        assert len(value) == length
        return value

    with mock.patch("os.urandom", urandom):
        blob, session_key = authenticate_real_plc(
            bytes.fromhex(vector["challenge"]),  # type: ignore[arg-type]
            get_public_key(vector["fingerprint"]),  # type: ignore[arg-type]
            KeyFamily[vector["family"]],  # type: ignore[index]
        )
    assert blob.hex() == vector["blob"]
    assert session_key.hex() == vector["session_key"]
    assert next(entropy, None) is None
