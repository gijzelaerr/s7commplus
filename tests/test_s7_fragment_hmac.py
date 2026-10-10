"""Independent OpenSSL vectors and negative tests for V3 fragment verification."""

import hashlib
import hmac
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from s7commplus._fragment_hmac import FragmentHMACVerifier, _continue_sha256
from s7commplus.error import S7IntegrityError

KEY = bytes(range(24))
VECTORS = json.loads((Path(__file__).parent / "fixtures/s7commplus/legacy_fragment_hmac.json").read_text())


def fragments() -> Iterator[bytes]:
    for v in VECTORS:
        data = bytes((i * 13 + v["size"]) % 256 for i in range(v["size"]))
        yield b"\x20" + bytes.fromhex(v["digest"]) + data


def test_openssl_legacy_vectors() -> None:
    verifier = FragmentHMACVerifier(KEY)
    for fragment in fragments():
        assert verifier.verify(fragment) == fragment[33:]


@pytest.mark.parametrize("index", range(len(VECTORS)))
def test_rejects_corruption_at_every_fragment(index: int) -> None:
    verifier = FragmentHMACVerifier(KEY)
    for i, fragment in enumerate(fragments()):
        if i == index:
            bad = bytearray(fragment)
            bad[-1] ^= 1
            with pytest.raises(S7IntegrityError):
                verifier.verify(bytes(bad))
            break
        verifier.verify(fragment)


def test_rejects_wrong_key_and_reordered_fragments() -> None:
    first, _second, third, *_ = fragments()
    with pytest.raises(S7IntegrityError):
        FragmentHMACVerifier(b"x" * 24).verify(first)
    verifier = FragmentHMACVerifier(KEY)
    verifier.verify(first)
    with pytest.raises(S7IntegrityError):
        verifier.verify(third)


def test_independent_fragment_compatibility() -> None:
    verifier = FragmentHMACVerifier(KEY)
    for data in [b"one", b"two", b"three"]:
        protected = b"\x20" + hmac.new(KEY, data, hashlib.sha256).digest() + data
        assert verifier.verify(protected) == data


@pytest.mark.parametrize("size", [0, 1, 55, 56, 63, 64, 65, 976])
def test_sha256_compression_against_hashlib(size: int) -> None:
    initial = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
    data = bytes(i % 256 for i in range(size))
    assert _continue_sha256(initial, data, len(data)) == hashlib.sha256(data).digest()


@pytest.mark.parametrize("protected", [b"", b"\x20", b"\x1f" + bytes(40), b"\x21" + bytes(40)])
def test_malformed_prefix_is_rejected(protected: bytes) -> None:
    with pytest.raises(S7IntegrityError, match="prefix"):
        FragmentHMACVerifier(KEY).verify(protected)


def test_session_key_length_is_validated() -> None:
    with pytest.raises(ValueError, match="24 bytes"):
        FragmentHMACVerifier(bytes(23))


def test_legacy_mode_cannot_switch_to_independent() -> None:
    verifier = FragmentHMACVerifier(KEY)
    first, second, *_ = fragments()
    verifier.verify(first)
    verifier.verify(second)
    data = b"unexpected independent fragment"
    with pytest.raises(S7IntegrityError):
        verifier.verify(b"\x20" + hmac.new(KEY, data, hashlib.sha256).digest() + data)


def test_independent_mode_cannot_switch_to_legacy() -> None:
    verifier = FragmentHMACVerifier(KEY)
    first, second, *_ = fragments()
    verifier.verify(first)
    data = b"independent second fragment"
    verifier.verify(b"\x20" + hmac.new(KEY, data, hashlib.sha256).digest() + data)
    with pytest.raises(S7IntegrityError):
        verifier.verify(second)


def test_new_response_requires_a_new_verifier() -> None:
    first, second, *_ = fragments()
    with pytest.raises(S7IntegrityError):
        FragmentHMACVerifier(KEY).verify(second)
    assert FragmentHMACVerifier(KEY).verify(first) == first[33:]


def _feed_forward_chain(key: bytes, payloads: list[bytes]) -> list[bytes]:
    """Build a feed-forward V3 chain: HMAC(key, previous digest || data)."""
    out: list[bytes] = []
    previous = b""
    for index, data in enumerate(payloads):
        digest = hmac.new(key, (b"" if index == 0 else previous) + data, hashlib.sha256).digest()
        out.append(b"\x20" + digest + data)
        previous = digest
    return out


def test_feed_forward_fragments_are_accepted() -> None:
    # PLCSIM Advanced chains continuation fragments as HMAC(key, previous digest || data).
    chunks = _feed_forward_chain(KEY, [b"one", b"two", b"three" * 200])
    verifier = FragmentHMACVerifier(KEY)
    for chunk in chunks:
        assert verifier.verify(chunk) == chunk[33:]


def test_feed_forward_mode_is_fixed_within_a_response() -> None:
    verifier = FragmentHMACVerifier(KEY)
    first, second = _feed_forward_chain(KEY, [b"one", b"two"])
    verifier.verify(first)
    verifier.verify(second)
    data = b"unexpected independent fragment"
    with pytest.raises(S7IntegrityError):
        verifier.verify(b"\x20" + hmac.new(KEY, data, hashlib.sha256).digest() + data)
    first, second, *_ = fragments()
    with pytest.raises(S7IntegrityError):
        verifier.verify(second)


def test_corrupted_feed_forward_continuation_is_rejected() -> None:
    chunks = _feed_forward_chain(KEY, [b"one", b"two"])
    bad = bytearray(chunks[1])
    bad[-1] ^= 1
    verifier = FragmentHMACVerifier(KEY)
    verifier.verify(chunks[0])
    with pytest.raises(S7IntegrityError):
        verifier.verify(bytes(bad))
