"""Automatic TLS selection: prefer TLS, continue in plaintext only when it is safe to."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Generator
from typing import Any

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.connection import _resolve_use_tls
from s7commplus.error import S7ConnectionError, S7TlsHandshakeError
from s7commplus.protocol import ProtocolVersion
from s7commplus.server import S7CommPlusServer
from tests.conftest import get_free_tcp_port
from tests.test_s7_tls import _certificate_sha256_hex, _generate_self_signed_cert, _has_cryptography


@pytest.fixture()
def plain_server() -> Generator[int, None, None]:
    """A V1 emulator without TLS: it closes the connection on a TLS ClientHello."""
    port = get_free_tcp_port()
    srv = S7CommPlusServer(protocol_version=ProtocolVersion.V1)
    srv.register_raw_db(1, bytearray(b"\x12\x34" + bytes(14)))
    srv.start(port=port)
    time.sleep(0.1)
    yield port
    srv.stop()


@pytest.fixture()
def tls_server() -> Generator[tuple[int, str], None, None]:
    """A V2 emulator with TLS; yields its port and the PEM certificate path."""
    cert_path, key_path = _generate_self_signed_cert()
    port = get_free_tcp_port()
    srv = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
    srv.register_raw_db(1, bytearray(16))
    srv.start(port=port, use_tls=True, tls_cert=cert_path, tls_key=key_path)
    time.sleep(0.1)
    yield port, cert_path
    srv.stop()
    os.unlink(cert_path)
    os.unlink(key_path)


# --- the use_tls argument -------------------------------------------------------


def test_resolve_use_tls() -> None:
    assert _resolve_use_tls(True) == (True, False)
    assert _resolve_use_tls(False) == (False, False)
    assert _resolve_use_tls("auto") == (True, True)


@pytest.mark.parametrize("value", ["preferred", "AUTO", "false", "off", "true", ""])
def test_any_other_string_is_refused(value: str) -> None:
    """A truthy "false" or "off" must not quietly turn TLS on."""
    with pytest.raises(ValueError, match="use_tls must be True, False or 'auto'"):
        _resolve_use_tls(value)
    with pytest.raises(ValueError, match="use_tls must be True, False or 'auto'"):
        S7CommPlusClient().connect("127.0.0.1", use_tls=value)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_async_any_other_string_is_refused() -> None:
    with pytest.raises(ValueError, match="use_tls must be True, False or 'auto'"):
        await S7CommPlusAsyncClient().connect("127.0.0.1", use_tls="off")  # type: ignore[arg-type]


def test_auto_with_legacy_s7_1500_is_refused() -> None:
    with pytest.raises(ValueError, match="legacy_s7_1500 requires use_tls=False"):
        S7CommPlusClient().connect("127.0.0.1", use_tls="auto", legacy_s7_1500=True)


# --- against the emulator -------------------------------------------------------


def test_tls_only_raises_a_typed_handshake_error(plain_server: int) -> None:
    """use_tls=True against a PLC without TLS raises S7TlsHandshakeError, the cause chained."""
    client = S7CommPlusClient()
    with pytest.raises(S7TlsHandshakeError, match="did not complete") as info:
        client.connect("127.0.0.1", port=plain_server, use_tls=True)
    assert info.value.__cause__ is not None
    assert not client.connected


def test_auto_continues_without_tls_when_the_plc_has_none(plain_server: int, caplog: pytest.LogCaptureFixture) -> None:
    client = S7CommPlusClient()
    with caplog.at_level(logging.WARNING, logger="s7commplus.connection"):
        client.connect("127.0.0.1", port=plain_server, use_tls="auto")
    try:
        assert client.connected
        assert client.peer_certificate_fingerprint() is None
        assert client.db_read(1, 0, 2) == b"\x12\x34"
        assert "continuing without TLS (use_tls='auto')" in caplog.text
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_auto_continues_without_tls_when_the_plc_has_none(
    plain_server: int, caplog: pytest.LogCaptureFixture
) -> None:
    client = S7CommPlusAsyncClient()
    with caplog.at_level(logging.WARNING, logger="s7commplus.connection"):
        await client.connect("127.0.0.1", port=plain_server, use_tls="auto")
    try:
        assert client.connected
        assert client.peer_certificate_fingerprint() is None
        assert await client.db_read(1, 0, 2) == b"\x12\x34"
        assert "continuing without TLS (use_tls='auto')" in caplog.text
    finally:
        await client.disconnect()


@pytest.fixture()
def cert_pair() -> Generator[tuple[str, str], None, None]:
    cert_path, key_path = _generate_self_signed_cert()
    yield cert_path, key_path
    os.unlink(cert_path)
    os.unlink(key_path)


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
@pytest.mark.parametrize(
    ("option", "reason"),
    [
        ("tls_cert_fingerprint", "a certificate is pinned"),
        ("tls_ca", "a CA certificate is configured"),
        ("tls_cert", "a client certificate is configured"),
        ("password", "a password is given"),
    ],
)
def test_auto_never_continues_without_tls_when_tls_was_configured(
    plain_server: int, cert_pair: tuple[str, str], option: str, reason: str
) -> None:
    """A pin, a CA, a client certificate or a password means the caller expects TLS."""
    cert_path, key_path = cert_pair
    options: dict[str, Any] = {
        "tls_cert_fingerprint": {"tls_cert_fingerprint": "00" * 32},
        "tls_ca": {"tls_ca": cert_path},
        "tls_cert": {"tls_cert": cert_path, "tls_key": key_path},
        "password": {"password": "secret"},
    }[option]
    client = S7CommPlusClient()
    with pytest.raises(S7TlsHandshakeError, match=f"does not fall back to plaintext because {reason}"):
        client.connect("127.0.0.1", port=plain_server, use_tls="auto", **options)
    assert not client.connected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("option", "reason"),
    [
        ({"tls_cert_fingerprint": "00" * 32}, "a certificate is pinned"),
        ({"password": "secret"}, "a password is given"),
    ],
)
async def test_async_auto_never_continues_without_tls_when_tls_was_configured(
    plain_server: int, option: dict[str, Any], reason: str
) -> None:
    client = S7CommPlusAsyncClient()
    with pytest.raises(S7TlsHandshakeError, match=f"does not fall back to plaintext because {reason}"):
        await client.connect("127.0.0.1", port=plain_server, use_tls="auto", **option)
    assert not client.connected


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
def test_auto_uses_tls_when_offered(tls_server: tuple[int, str]) -> None:
    port, cert_path = tls_server
    for options in ({}, {"tls_cert_fingerprint": _certificate_sha256_hex(cert_path)}):
        client = S7CommPlusClient()
        client.connect("127.0.0.1", port=port, use_tls="auto", **options)
        try:
            assert client.peer_certificate_fingerprint() == bytes.fromhex(_certificate_sha256_hex(cert_path))
        finally:
            client.disconnect()


@pytest.mark.skipif(not _has_cryptography, reason="requires cryptography package")
@pytest.mark.asyncio
async def test_async_auto_uses_tls_when_offered(tls_server: tuple[int, str]) -> None:
    port, cert_path = tls_server
    for options in ({}, {"tls_cert_fingerprint": _certificate_sha256_hex(cert_path)}):
        client = S7CommPlusAsyncClient()
        await client.connect("127.0.0.1", port=port, use_tls="auto", **options)
        try:
            assert client.peer_certificate_fingerprint() == bytes.fromhex(_certificate_sha256_hex(cert_path))
        finally:
            await client.disconnect()


# --- only a failed handshake falls back; every reconnect tries TLS first ------------


def test_a_failure_after_the_handshake_never_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """E.g. a refused password or a rejected session: retrying in the clear would leak it."""
    client = S7CommPlusClient()
    seen: list[bool] = []

    def fake_open() -> None:
        assert client._connect_params is not None
        seen.append(client._connect_params["use_tls"])
        raise S7ConnectionError("session setup was rejected by the PLC")

    monkeypatch.setattr(client, "_open_connection_with_key_fallback", fake_open)
    with pytest.raises(S7ConnectionError, match="session setup was rejected"):
        client.connect("plc", use_tls="auto")
    assert seen == [True]


@pytest.mark.asyncio
async def test_async_a_failure_after_the_handshake_never_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    client = S7CommPlusAsyncClient()
    seen: list[bool] = []

    async def fake_open() -> None:
        assert client._connect_params is not None
        seen.append(client._connect_params["use_tls"])
        raise S7ConnectionError("session setup was rejected by the PLC")

    monkeypatch.setattr(client, "_open_connection_with_key_fallback", fake_open)
    with pytest.raises(S7ConnectionError, match="session setup was rejected"):
        await client.connect("plc", use_tls="auto")
    assert seen == [True]


def test_every_reconnect_tries_tls_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fallback holds for one connection only, so one failed handshake cannot pin plaintext."""
    client = S7CommPlusClient()
    seen: list[bool] = []

    def fake_open() -> None:
        assert client._connect_params is not None
        seen.append(client._connect_params["use_tls"])
        if client._connect_params["use_tls"]:
            raise S7TlsHandshakeError("TLS handshake with the PLC did not complete: Connection closed by peer")

    monkeypatch.setattr(client, "_open_connection_with_key_fallback", fake_open)
    client.connect("plc", use_tls="auto")
    client._open_connection()  # what a reconnect runs
    assert seen == [True, False, True, False]


@pytest.mark.asyncio
async def test_async_every_reconnect_tries_tls_first(monkeypatch: pytest.MonkeyPatch) -> None:
    client = S7CommPlusAsyncClient()
    seen: list[bool] = []

    async def fake_open() -> None:
        assert client._connect_params is not None
        seen.append(client._connect_params["use_tls"])
        if client._connect_params["use_tls"]:
            raise S7TlsHandshakeError("TLS handshake with the PLC did not complete: Connection closed by peer")

    monkeypatch.setattr(client, "_open_connection_with_key_fallback", fake_open)
    await client.connect("plc", use_tls="auto")
    await client._open_connection()
    assert seen == [True, False, True, False]


def test_reconnect_keeps_the_automatic_mode(plain_server: int) -> None:
    """browse()'s reconnect after a dropped connection reopens with "auto" again."""
    client = S7CommPlusClient()
    client.connect("127.0.0.1", port=plain_server, use_tls="auto")
    try:
        client._reconnect()
        assert client.connected
        assert client._connect_params is not None and client._connect_params["auto_tls"]
        assert client.db_read(1, 0, 2) == b"\x12\x34"
    finally:
        client.disconnect()


@pytest.mark.asyncio
async def test_async_reconnect_keeps_the_automatic_mode(plain_server: int) -> None:
    """The async reconnect re-runs connect() from the stored parameters, which must accept them."""
    client = S7CommPlusAsyncClient()
    await client.connect("127.0.0.1", port=plain_server, use_tls="auto")
    try:
        await client._reconnect()
        assert client.connected
        assert client._connect_params is not None and client._connect_params["auto_tls"]
        assert await client.db_read(1, 0, 2) == b"\x12\x34"
    finally:
        await client.disconnect()
