"""Exceptions survive pickle, copy and deepcopy with their message and attributes.

Errors cross process boundaries (multiprocessing, concurrent.futures) by
pickling, which rebuilds them from ``args``. A subclass whose constructor takes
other arguments than the message used to fail there.
"""

import copy
import pickle
from typing import Callable

import pytest

from s7commplus.connection import (
    FamilyOnlyFingerprintError,
    SessionKeyAuthenticationDependencyError,
    SessionKeyCandidateRejectedError,
)
from s7commplus.error import (
    S7AuthenticationError,
    S7ConnectionError,
    S7Error,
    S7IntegrityError,
    S7PacketLostError,
    S7ProtocolError,
    S7RateLimitError,
    S7ReturnValueError,
    S7StalePacketError,
    S7TimeoutError,
)
from s7commplus.v1_session_key.keys import UnknownPublicKeyError

ROUND_TRIPS: list[Callable[[BaseException], BaseException]] = [
    lambda error: pickle.loads(pickle.dumps(error)),
    copy.copy,
    copy.deepcopy,
]

ERRORS: list[BaseException] = [
    S7Error("base", 0x1234),
    S7ConnectionError("connection"),
    S7ProtocolError("protocol", 7),
    S7IntegrityError("integrity"),
    S7TimeoutError("timeout"),
    S7AuthenticationError("authentication"),
    S7RateLimitError("rate limit"),
    S7ReturnValueError("EXPLORE failed", 0x8020AB001992FFF4, b"\x00\x01"),
    S7StalePacketError("stale"),
    S7PacketLostError("lost"),
    SessionKeyCandidateRejectedError("rejected"),
    SessionKeyAuthenticationDependencyError("dependency"),
    FamilyOnlyFingerprintError(3),
    UnknownPublicKeyError("00:11:22"),
]


@pytest.mark.parametrize("round_trip", ROUND_TRIPS, ids=["pickle", "copy", "deepcopy"])
@pytest.mark.parametrize("error", ERRORS, ids=lambda error: type(error).__name__)
def test_error_round_trips(error: BaseException, round_trip: Callable[[BaseException], BaseException]) -> None:
    restored = round_trip(error)

    assert type(restored) is type(error)
    assert str(restored) == str(error)
    assert restored.args == error.args
    assert vars(restored) == vars(error)


def test_family_only_fingerprint_error_keeps_family() -> None:
    restored = pickle.loads(pickle.dumps(FamilyOnlyFingerprintError(3)))

    assert isinstance(restored, FamilyOnlyFingerprintError)
    assert restored.family == 3
    assert restored.error_code is None


def test_unknown_public_key_error_keeps_fingerprint() -> None:
    restored = pickle.loads(pickle.dumps(UnknownPublicKeyError("00:11:22")))

    assert isinstance(restored, UnknownPublicKeyError)
    assert restored.fingerprint == "00:11:22"
