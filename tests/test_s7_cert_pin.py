"""Pinned TLS certificate fingerprint parsing and verification."""

from __future__ import annotations

import hashlib
from typing import Any, Optional

import pytest

from s7commplus.connection import _parse_certificate_fingerprint, _verify_pinned_certificate
from s7commplus.error import S7CertificateError

_FINGERPRINT = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
_FINGERPRINT_BYTES = bytes.fromhex(_FINGERPRINT.replace(":", ""))


class _StubSslObject:
    """Minimal stand-in exposing just the ssl.SSLObject method the check uses."""

    def __init__(self, der: Optional[bytes]) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> Any:
        return self._der if binary_form else None


def test_parse_accepts_colon_space_and_plain_hex() -> None:
    assert _parse_certificate_fingerprint(_FINGERPRINT) == _FINGERPRINT_BYTES
    assert _parse_certificate_fingerprint(_FINGERPRINT_BYTES.hex()) == _FINGERPRINT_BYTES
    spaced = " ".join(_FINGERPRINT_BYTES.hex()[i : i + 2] for i in range(0, 64, 2))
    assert _parse_certificate_fingerprint(spaced) == _FINGERPRINT_BYTES


def test_parse_accepts_the_openssl_output_line() -> None:
    """The whole line ``openssl x509 -noout -fingerprint -sha256`` prints can be pasted."""
    assert _parse_certificate_fingerprint(f"sha256 Fingerprint={_FINGERPRINT}") == _FINGERPRINT_BYTES
    assert _parse_certificate_fingerprint(f"SHA256 Fingerprint={_FINGERPRINT}\n") == _FINGERPRINT_BYTES
    assert _parse_certificate_fingerprint(f"\t{_FINGERPRINT_BYTES.hex()}\r\n") == _FINGERPRINT_BYTES


@pytest.mark.parametrize("bad", ["", "aabb", "zz" * 32, "00" * 31, "00" * 33, "Fingerprint="])
def test_parse_rejects_bad_fingerprints(bad: str) -> None:
    with pytest.raises(ValueError):
        _parse_certificate_fingerprint(bad)


def test_verify_returns_the_observed_digest_when_unpinned() -> None:
    der = b"certificate"
    assert _verify_pinned_certificate(_StubSslObject(der), None) == hashlib.sha256(der).digest()


def test_verify_passes_when_the_pin_matches() -> None:
    der = b"certificate"
    digest = hashlib.sha256(der).digest()
    assert _verify_pinned_certificate(_StubSslObject(der), digest) == digest


def test_verify_rejects_a_mismatched_pin() -> None:
    with pytest.raises(S7CertificateError, match="does not match"):
        _verify_pinned_certificate(_StubSslObject(b"certificate"), bytes(32))


def test_verify_rejects_a_missing_certificate() -> None:
    with pytest.raises(S7CertificateError, match="did not present"):
        _verify_pinned_certificate(_StubSslObject(None), bytes(32))


def test_pinning_requires_tls() -> None:
    """A pinned certificate must never be used on a plaintext connection."""
    from s7commplus.connection import S7CommPlusConnection

    conn = S7CommPlusConnection("127.0.0.1")
    with pytest.raises(ValueError, match="requires use_tls=True"):
        conn.connect(use_tls=False, tls_cert_fingerprint="00" * 32)


def test_client_refuses_a_pin_without_tls_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    from s7commplus import Client

    def no_network(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("connect() opened a connection before validating the pin")

    monkeypatch.setattr(Client, "_open_connection", no_network)
    client = Client()
    with pytest.raises(ValueError, match="requires use_tls=True"):
        client.connect("127.0.0.1", tls_cert_fingerprint="00" * 32)
    with pytest.raises(ValueError, match="64 hex characters"):
        client.connect("127.0.0.1", use_tls=True, tls_cert_fingerprint="")
    assert not client.connected


@pytest.mark.asyncio
async def test_async_client_refuses_a_pin_without_tls_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    """The async client must refuse a plaintext pin too (it used to connect in the clear)."""
    from s7commplus import AsyncClient

    async def no_network(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("connect() opened a connection before validating the pin")

    monkeypatch.setattr(AsyncClient, "_open_connection", no_network)
    client = AsyncClient()
    with pytest.raises(ValueError, match="requires use_tls=True"):
        await client.connect("127.0.0.1", tls_cert_fingerprint="00" * 32)
    with pytest.raises(ValueError, match="64 hex characters"):
        await client.connect("127.0.0.1", use_tls=True, tls_cert_fingerprint="")
    assert not client.connected
