"""SeedTransform's Transform7/Monolith1/Monolith2 chain is an x-only ECDH ladder."""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from unittest import mock

import pytest

from s7commplus.v1_session_key.real_plc import curve, seed
from old.family0 import encoding, transform7_compact, transform12_compact
from old.family0 import seed_transform as old_seed_transform
from old.family0._generated import monolith2
from old.family0._generated.data import TRANSFORM7_DATA
from s7commplus.v1_session_key.keys import KeyFamily, fingerprints_for_family, get_public_key
from tools import trace_scalar_seed_boundary as boundary
from tools.recover_scalar_encodings import scalar_xor_mask
from tools.verify_v1_session_key_evidence import PROVENANCE

_GENERATOR = bytes(TRANSFORM7_DATA[0xD8:0x100])
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


def _transform7_value(prng1: bytes, prng2: bytes, source: bytes) -> int:
    span = bytearray(transform7_compact.DESTINATION_SIZE)
    transform7_compact.execute(span, bytearray(prng1), bytearray(prng2), source)
    return encoding.span_value(span)


def test_domain_parameters() -> None:
    assert _GENERATOR == curve.GENERATOR_X.to_bytes(20, "little") + curve.GENERATOR_Y.to_bytes(20, "little")
    generator = (curve.GENERATOR_X, curve.GENERATOR_Y)
    assert _is_probable_prime(curve.P) and _is_probable_prime(curve.ORDER)
    assert (curve.GENERATOR_Y**2 - (curve.GENERATOR_X**3 + curve.A * curve.GENERATOR_X + curve.B)) % curve.P == 0
    assert _affine_multiply(curve.ORDER, generator) is None
    assert curve.x_multiply(curve.ORDER, curve.GENERATOR_X) == 0
    assert transform12_compact._CONSTANTS[58] % curve.P == curve.B  # The ladder's doubling constant.


def test_scalar_mask_is_the_source_derived_branch_mask() -> None:
    assert curve.SCALAR_MASK == scalar_xor_mask()


def test_ladder_matches_affine_arithmetic() -> None:
    rng = random.Random(5400)
    generator = (curve.GENERATOR_X, curve.GENERATOR_Y)
    for scalar in (1, 2, 3, curve.ORDER - 1, *(rng.getrandbits(160) for _ in range(8))):
        point = _affine_multiply(rng.randrange(1, curve.ORDER), generator)
        assert point is not None
        expected = _affine_multiply(scalar, point)
        assert curve.x_multiply(scalar, point[0]) == (0 if expected is None else expected[0])
    assert curve.x_multiply(0, curve.GENERATOR_X) == 0


@pytest.mark.parametrize("source", [_GENERATOR, *_PUBLIC_KEYS], ids=lambda source: source[:4].hex())
def test_ladder_is_the_value_transform7_decodes_to(source: bytes) -> None:
    rng = random.Random(source)
    prng1, prng2 = rng.randbytes(20), rng.randbytes(20)
    expected = _transform7_value(prng1, prng2, source)
    assert curve.x_multiply(curve.ladder_scalar(prng2), int.from_bytes(source[:20], "little")) == expected


def test_catalogue_contains_keys_on_the_curve_and_its_twist() -> None:
    def on_curve(x: int) -> bool:
        return pow((x**3 + curve.A * x + curve.B) % curve.P, (curve.P - 1) // 2, curve.P) == 1

    kinds = {on_curve(int.from_bytes(key[:20], "little")) for key in _PUBLIC_KEYS}
    assert kinds == {True, False}  # The x-only ladder covers both; Transform7 agrees on each above.


@pytest.mark.parametrize("number", [0, 1])
def test_upstream_transform7_known_answers(number: int) -> None:
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))["transform7_vectors"][number]
    fields = {key: bytes.fromhex(field["hex"]) for key, field in record["fields"].items()}
    x = int.from_bytes(fields["source"][:20], "little")
    expected = encoding.span_value(fields["destination"])
    assert curve.x_multiply(curve.ladder_scalar(fields["prng2"]), x) == expected


def test_ignored_inputs_and_value_preserving_monoliths() -> None:
    rng = random.Random(5401)
    prng2 = rng.randbytes(20)
    values = {_transform7_value(rng.randbytes(20), prng2, _GENERATOR[:20] + rng.randbytes(20)) for _ in range(3)}
    assert values == {curve.x_multiply(curve.ladder_scalar(prng2), curve.GENERATOR_X)}
    for _ in range(3):
        span = bytearray(transform7_compact.DESTINATION_SIZE)
        transform7_compact.execute(span, bytearray(rng.randbytes(20)), bytearray(rng.randbytes(20)), rng.choice(_PUBLIC_KEYS))
        value = encoding.span_value(span)
        old_seed_transform._monolith1_loop(span)
        assert encoding.span_value(span) == value
        serialized = bytearray(20)
        monolith2.execute(serialized, bytes(span))
        assert serialized == value.to_bytes(20, "little")


def test_transform7_is_not_modular_for_a_small_source() -> None:
    """For x = 5 the original's result depends on its blinding inputs; the ladder is the true multiple."""
    rng = random.Random(5402)
    prng2 = rng.randbytes(20)
    source = (5).to_bytes(20, "little")
    values = {_transform7_value(rng.randbytes(20), prng2, source + rng.randbytes(20)) for _ in range(3)}
    assert len(values) > 1
    scalar = curve.ladder_scalar(prng2)
    assert curve.x_multiply(scalar, 5) not in values
    split = rng.randrange(1, curve.ORDER)
    composed = curve.x_multiply(scalar * pow(split, -1, curve.ORDER) % curve.ORDER, curve.x_multiply(split, 5))
    assert composed == curve.x_multiply(scalar, 5)


def _entropy(rng: random.Random, forced: list[bytes] | None = None) -> Iterator[bytes]:
    yield from forced or []
    while True:
        yield rng.randbytes(20)


def _run(implementation: object, public_key: bytes, pre_seed: int, entropy: Iterator[bytes]) -> tuple[bytes, int]:
    requests = 0

    def urandom(length: int) -> bytes:
        nonlocal requests
        assert length == 20
        requests += 1
        return next(entropy)

    destination = bytearray(seed.SEED_LENGTH)
    with mock.patch("os.urandom", urandom):
        implementation(destination, public_key, pre_seed)  # type: ignore[operator]
    return bytes(destination), requests


@pytest.mark.parametrize("trial", range(4))
def test_seed_transform_matches_the_transform7_chain(trial: int) -> None:
    rng = random.Random(5403 + trial)
    public_key, pre_seed = rng.choice(_PUBLIC_KEYS), rng.getrandbits(160)
    outputs = [
        _run(implementation, public_key, pre_seed, _entropy(random.Random(trial)))
        for implementation in (seed.write_seed, old_seed_transform.reference_execute_value)
    ]
    assert outputs[0] == outputs[1]
    assert outputs[0][1] == 2


def test_seed_transform_retries_an_infinite_ephemeral_like_the_transform7_chain() -> None:
    forced = [bytes(20), curve.SCALAR_MASK.to_bytes(20, "little")]  # prng1, then the scalar 0.
    outputs = [
        _run(implementation, _PUBLIC_KEYS[0], 0, _entropy(random.Random(5404), forced))
        for implementation in (seed.write_seed, old_seed_transform.reference_execute_value)
    ]
    assert outputs[0] == outputs[1]
    assert outputs[0][1] == 3


def test_seed_transform_runtime_does_not_execute_transform7() -> None:
    with (
        mock.patch.object(transform7_compact, "execute", side_effect=AssertionError("Transform7 executed")),
        mock.patch.object(monolith2, "execute", side_effect=AssertionError("Monolith2 executed")),
    ):
        _run(seed.write_seed, _GENERATOR, 0, _entropy(random.Random(5405)))


def test_negative_scalars_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        curve.x_multiply(-1, curve.GENERATOR_X)


class _Exhausted(Exception):
    pass


@pytest.mark.parametrize("case", boundary.cases(), ids=lambda case: case.name)
def test_runtime_is_the_modular_candidate_on_constructed_carry_cases(case: boundary.Case) -> None:
    """Where Transform7's lost carries change the original seed, the runtime follows the true ECDH."""
    entropy = iter((case.prng1.to_bytes(20, "little"), case.selector.to_bytes(20, "little")))

    def urandom(length: int) -> bytes:
        try:
            return next(entropy)
        except StopIteration:
            raise _Exhausted from None

    destination = bytearray(seed.SEED_LENGTH)
    with mock.patch("os.urandom", urandom):
        try:
            old_seed_transform.execute(destination, case.public_key, case.transform1)
            runtime: bytes | None = bytes(destination)
        except _Exhausted:
            runtime = None
    candidate, original = boundary.first_nonce(case, "modular"), boundary.first_nonce(case, "original")
    assert runtime == candidate.seed
    # The setup-carry difference is erased before the seed; the other two carries reach it.
    assert (runtime == original.seed) == (case.name not in {"synthetic-on-curve-carry", "vendored-key-scalar-carry"})
