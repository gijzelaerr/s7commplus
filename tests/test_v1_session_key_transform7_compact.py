"""Byte-equivalence of the runtime Transform7 with the retained original."""

from __future__ import annotations

import random
import struct
from unittest.mock import patch

import pytest

from s7commplus.v1_session_key import keys
from s7commplus.v1_session_key.real_plc import seed
from old.family0 import seed_transform as old_seed_transform
from old.family0 import transform7, transform7_compact, transform12, transform12_compact
from old.family0._generated.data import TRANSFORM7_DATA
from tools import transform12_integer_model as arithmetic
from tools.recover_monolith4_span_identity import normalized_span
from tools.transform7_setup_integer import model as proven_setup


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_BASE_POINT = bytes(TRANSFORM7_DATA[0xD8:])
# Reachable synthetic input whose setup hits BigIntAddition's lost-carry exception.
_CARRY_WITNESS = (1456322070154714087054275448276265639382807574476).to_bytes(20, "little")
_SOURCES = [_BASE_POINT] + [keys.get_public_key(fp) for family in (0, 1) for fp in keys.fingerprints_for_family(family)]


class _Stop(Exception):
    pass


def _original_setup_context(prng1: bytes, source: bytes) -> bytes:
    captured: list[bytes] = []

    def stop(context: bytearray, index: int, count: int) -> None:
        captured.append(bytes(context))
        raise _Stop

    with patch.object(transform12, "execute", stop), pytest.raises(_Stop):
        transform7.execute(bytearray(72), bytearray(prng1), bytearray(20), source)
    return captured[0]


def _compact_setup_context(prng1: bytes, source: bytes) -> bytes:
    context = [0] * transform12_compact.SLOTS
    x, y = (int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20))
    transform7_compact._setup(context, x, y, int.from_bytes(prng1, "little"))
    return b"".join(transform12_compact.encode(value) for value in context)


def _setup_cases() -> list[tuple[bytes, bytes]]:
    rng = random.Random(0x7C0)
    cases = [(_CARRY_WITNESS, _BASE_POINT), (bytes(20), _BASE_POINT), (b"\xff" * 20, _BASE_POINT)]
    cases += [(rng.randbytes(20), source) for source in _SOURCES for _ in range(2)]
    cases += [(rng.randbytes(20), rng.randbytes(40)) for _ in range(20)]
    return cases


def test_bundled_payload_is_the_decoded_bundled_span() -> None:
    assert normalized_span(struct.unpack("<18I", TRANSFORM7_DATA[:0x48])) == (0, 0)
    assert normalized_span(struct.unpack("<18I", TRANSFORM7_DATA[0x48:0x90])) == (transform7_compact._BUNDLED_PAYLOAD, 0)


def test_setup_context_is_byte_identical_to_the_original_monolith_setup() -> None:
    for prng1, source in _setup_cases():
        assert _compact_setup_context(prng1, source) == _original_setup_context(prng1, source)


def test_setup_slots_match_the_proven_integer_model() -> None:
    for prng1, source in _setup_cases():
        context = _compact_setup_context(prng1, source)
        x, y = (int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20))
        slots = tuple(arithmetic.decode(context[slot * 24 : (slot + 1) * 24]) for slot in (46, 48, 70, 94))
        assert slots == proven_setup(x, y, int.from_bytes(prng1, "little")).slots


def test_execute_matches_the_original_on_the_carry_witness() -> None:
    for prng2 in (b"\x01" + bytes(19),):
        expected, actual = bytearray(72), bytearray(72)
        transform7.execute(expected, bytearray(_CARRY_WITNESS), bytearray(prng2), _BASE_POINT)
        transform7_compact.execute(actual, bytearray(_CARRY_WITNESS), bytearray(prng2), _BASE_POINT)
        assert actual == expected


@pytest.mark.slow
def test_execute_matches_the_original_for_every_public_key() -> None:
    rng = random.Random(0x7C1)
    for source in _SOURCES:
        for prng1, prng2 in ((rng.randbytes(20), rng.randbytes(20)), (b"\xff" * 20, b"\xff" * 20)):
            expected, actual = bytearray(72), bytearray(72)
            transform7.execute(expected, bytearray(prng1), bytearray(prng2), source)
            transform7_compact.execute(actual, bytearray(prng1), bytearray(prng2), source)
            assert actual == expected


def test_only_the_reference_seed_transform_calls_the_compact_transform7() -> None:
    assert not hasattr(seed, "transform7") and not hasattr(seed, "transform7_compact")
    assert old_seed_transform.transform7_compact is transform7_compact
