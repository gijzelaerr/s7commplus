"""SeedTransform's Transform7/Monolith1/Monolith2 chain is an x-only ECDH ladder.

The Transform7 answers below were recorded from the retired HarpoS7 ports and
recovery tools before they moved to the s7commplus-research repository.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from unittest import mock

import pytest

from s7commplus.v1_session_key.keys import KeyFamily, fingerprints_for_family, get_public_key
from s7commplus.v1_session_key.real_plc import curve, seed

_FIXTURES = Path(__file__).parent / "fixtures" / "family0"
_VECTORS = json.loads((_FIXTURES / "reference_vectors.json").read_text(encoding="utf-8"))
_PROVENANCE = json.loads((_FIXTURES / "provenance.json").read_text(encoding="utf-8"))
_PUBLIC_KEYS = [get_public_key(fingerprint)[:40] for family in KeyFamily for fingerprint in fingerprints_for_family(family)]

Point = tuple[int, int] | None


def _affine_add(first: Point, second: Point) -> Point:
    if first is None or second is None:
        return second if first is None else first
    (x1, y1), (x2, y2) = first, second
    if x1 == x2 and (y1 + y2) % curve.P == 0:
        return None
    if x1 == x2:
        slope = (3 * x1 * x1 + curve.A) * pow(2 * y1, -1, curve.P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, curve.P)
    x3 = (slope * slope - x1 - x2) % curve.P
    return x3, (slope * (x1 - x3) - y1) % curve.P


def _affine_multiply(scalar: int, point: Point) -> Point:
    result: Point = None
    while scalar:
        if scalar & 1:
            result = _affine_add(result, point)
        point = _affine_add(point, point)
        scalar >>= 1
    return result


def _is_probable_prime(value: int) -> bool:
    exponent, shift = value - 1, 0
    while exponent % 2 == 0:
        exponent, shift = exponent // 2, shift + 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        witness = pow(base, exponent, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shift - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def test_domain_parameters() -> None:
    generator = (curve.GENERATOR_X, curve.GENERATOR_Y)
    assert _is_probable_prime(curve.P) and _is_probable_prime(curve.ORDER)
    assert (curve.GENERATOR_Y**2 - (curve.GENERATOR_X**3 + curve.A * curve.GENERATOR_X + curve.B)) % curve.P == 0
    assert _affine_multiply(curve.ORDER, generator) is None
    assert curve.x_multiply(curve.ORDER, curve.GENERATOR_X) == 0


def test_ladder_matches_affine_arithmetic() -> None:
    rng = random.Random(5400)
    generator = (curve.GENERATOR_X, curve.GENERATOR_Y)
    for scalar in (1, 2, 3, curve.ORDER - 1, *(rng.getrandbits(160) for _ in range(8))):
        point = _affine_multiply(rng.randrange(1, curve.ORDER), generator)
        assert point is not None
        expected = _affine_multiply(scalar, point)
        assert curve.x_multiply(scalar, point[0]) == (0 if expected is None else expected[0])
    assert curve.x_multiply(0, curve.GENERATOR_X) == 0


@pytest.mark.parametrize("vector", _VECTORS["transform7_ladder"], ids=lambda vector: vector["source"][:8])
def test_ladder_is_the_value_transform7_decodes_to(vector: dict[str, str]) -> None:
    """The generator and every vendored public key, with the value HarpoS7's Transform7 output decoded to."""
    x = int.from_bytes(bytes.fromhex(vector["source"])[:20], "little")
    assert curve.x_multiply(curve.ladder_scalar(bytes.fromhex(vector["prng2"])), x) == int(vector["x"], 16)


def test_ladder_vectors_cover_the_generator_and_every_vendored_key() -> None:
    sources = {bytes.fromhex(vector["source"]) for vector in _VECTORS["transform7_ladder"]}
    generator = curve.GENERATOR_X.to_bytes(20, "little") + curve.GENERATOR_Y.to_bytes(20, "little")
    assert sources == {generator, *_PUBLIC_KEYS}


def test_catalogue_contains_keys_on_the_curve_and_its_twist() -> None:
    def on_curve(x: int) -> bool:
        return pow((x**3 + curve.A * x + curve.B) % curve.P, (curve.P - 1) // 2, curve.P) == 1

    kinds = {on_curve(int.from_bytes(key[:20], "little")) for key in _PUBLIC_KEYS}
    assert kinds == {True, False}  # The x-only ladder covers both; Transform7 agrees on each above.


@pytest.mark.parametrize("record", _PROVENANCE["transform7_vectors"], ids=lambda record: record["name"])
def test_upstream_transform7_known_answers(record: dict[str, object]) -> None:
    fields = {key: bytes.fromhex(field["hex"]) for key, field in record["fields"].items()}  # type: ignore[attr-defined]
    x = int.from_bytes(fields["source"][:20], "little")
    expected = int(_VECTORS["upstream_decoded"]["transform7_x"][record["name"]], 16)
    assert curve.x_multiply(curve.ladder_scalar(fields["prng2"]), x) == expected


def _run(public_key: bytes, pre_seed: int, entropy: list[str]) -> tuple[bytes, int]:
    values = iter(bytes.fromhex(value) for value in entropy)
    requests = 0

    def urandom(length: int) -> bytes:
        nonlocal requests
        assert length == 20
        requests += 1
        return next(values)

    destination = bytearray(seed.SEED_LENGTH)
    with mock.patch("os.urandom", urandom):
        seed.write_seed(destination, public_key, pre_seed)
    return bytes(destination), requests


@pytest.mark.parametrize(
    "vector", _VECTORS["write_seed"], ids=lambda vector: f"{vector['pre_seed'][:8]}-{len(vector['entropy'])}"
)
def test_seed_transform_matches_the_transform7_chain(vector: dict[str, object]) -> None:
    """The seed HarpoS7's Transform7/Monolith1/Monolith2 chain wrote for the same inputs and entropy.

    The last vector forces the scalar 0 first, so both retry an infinite ephemeral and draw a third value.
    """
    entropy: list[str] = vector["entropy"]  # type: ignore[assignment]
    result, requests = _run(bytes.fromhex(vector["public_key"]), int(vector["pre_seed"], 16), entropy)  # type: ignore[arg-type]
    assert result.hex() == vector["seed"]
    assert requests == len(entropy)


def test_seed_vectors_include_a_retried_infinite_ephemeral() -> None:
    assert sorted(len(vector["entropy"]) for vector in _VECTORS["write_seed"]) == [2, 2, 2, 2, 3]


def test_negative_scalars_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        curve.x_multiply(-1, curve.GENERATOR_X)


class _Exhausted(Exception):
    pass


@pytest.mark.parametrize("case", _VECTORS["carry_cases"], ids=lambda case: case["name"])
def test_runtime_is_the_modular_candidate_on_constructed_carry_cases(case: dict[str, object]) -> None:
    """Where Transform7's lost carries change the original seed, the runtime follows the true ECDH.

    The setup-carry difference is erased before the seed; the on-curve and scalar carries reach it,
    so for those two the original HarpoS7 seed differs from the recorded one.
    """
    entropy = iter(bytes.fromhex(value) for value in case["entropy"])  # type: ignore[attr-defined]

    def urandom(length: int) -> bytes:
        try:
            return next(entropy)
        except StopIteration:
            raise _Exhausted from None

    destination = bytearray(seed.SEED_LENGTH)
    with mock.patch("os.urandom", urandom):
        try:
            seed.write_seed(destination, bytes.fromhex(case["public_key"]), int(case["pre_seed"], 16))  # type: ignore[arg-type]
            runtime: str | None = destination.hex()
        except _Exhausted:
            runtime = None
    assert runtime == case["seed"]
    assert case["original_seed_differs"] == (case["name"] in {"synthetic-on-curve-carry", "vendored-key-scalar-carry"})
