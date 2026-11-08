"""Connection-type (COTP TSAP) selection."""

from __future__ import annotations

import struct
import threading
from collections.abc import Generator

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.connection import S7CommPlusConnection
from s7commplus.protocol import (
    S7COMMPLUS_LOCAL_TSAP,
    S7COMMPLUS_REMOTE_TSAP,
    ConnectionType,
    remote_tsap_for_connection_type,
)
from s7commplus.server import S7CommPlusServer


class TestRemoteTsapForConnectionType:
    """Each connection type maps to its called TSAP string."""

    @pytest.mark.parametrize(
        ("connection_type", "expected"),
        [
            (ConnectionType.HMI, b"SIMATIC-ROOT-HMI"),
            (ConnectionType.ES, b"SIMATIC-ROOT-ES"),
            (ConnectionType.PG, b"SIMATIC-ROOT-PG"),
        ],
    )
    def test_enum_members(self, connection_type: ConnectionType, expected: bytes) -> None:
        assert remote_tsap_for_connection_type(connection_type) == expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("hmi", b"SIMATIC-ROOT-HMI"),
            ("HMI", b"SIMATIC-ROOT-HMI"),
            ("es", b"SIMATIC-ROOT-ES"),
            (" ES ", b"SIMATIC-ROOT-ES"),
            ("pg", b"SIMATIC-ROOT-PG"),
        ],
    )
    def test_string_names_are_case_insensitive(self, name: str, expected: bytes) -> None:
        assert remote_tsap_for_connection_type(name) == expected

    def test_enum_value_as_int(self) -> None:
        assert remote_tsap_for_connection_type(int(ConnectionType.ES)) == b"SIMATIC-ROOT-ES"

    @pytest.mark.parametrize("bad", ["scada", "", "hmi2", 99])
    def test_unknown_raises_value_error(self, bad: object) -> None:
        with pytest.raises(ValueError, match="Unknown connection type"):
            remote_tsap_for_connection_type(bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize("boolean", [True, False])
    def test_booleans_are_rejected_not_treated_as_ints(self, boolean: bool) -> None:
        # bool is an int subclass: True must not silently select ES.
        with pytest.raises(ValueError, match="Unknown connection type"):
            remote_tsap_for_connection_type(boolean)  # type: ignore[arg-type]


class TestConnectionDefaults:
    """Without a connection type the historical HMI TSAP stays unchanged."""

    def test_default_connection_uses_hmi_tsap(self) -> None:
        connection = S7CommPlusConnection("192.0.2.1")
        assert connection._iso_conn.remote_tsap == S7COMMPLUS_REMOTE_TSAP

    def test_es_connection_type_selects_es_tsap(self) -> None:
        connection = S7CommPlusConnection("192.0.2.1", connection_type="es")
        assert connection._iso_conn.remote_tsap == b"SIMATIC-ROOT-ES"
        assert connection._iso_conn.local_tsap == S7COMMPLUS_LOCAL_TSAP

    def test_connection_type_by_enum(self) -> None:
        connection = S7CommPlusConnection("192.0.2.1", connection_type=ConnectionType.PG)
        assert connection._iso_conn.remote_tsap == b"SIMATIC-ROOT-PG"

    def test_invalid_connection_type_raises_at_construction(self) -> None:
        with pytest.raises(ValueError, match="Unknown connection type"):
            S7CommPlusConnection("192.0.2.1", connection_type="scada")


class TestClientValidatesConnectionType:
    """connect() rejects an unknown connection type before touching the network."""

    def test_sync_client_rejects_early(self) -> None:
        client = S7CommPlusClient()
        with pytest.raises(ValueError, match="Unknown connection type"):
            client.connect("192.0.2.1", port=102, connection_type="scada")

    @pytest.mark.asyncio
    async def test_async_client_rejects_early(self) -> None:
        client = S7CommPlusAsyncClient()
        with pytest.raises(ValueError, match="Unknown connection type"):
            await client.connect("192.0.2.1", port=102, connection_type="scada")


class _CapturingServer:
    """A TCP server that records the first COTP Connection Request it receives.

    The emulator answers any well-formed COTP CR, so it cannot be used to
    observe which TSAP was called; this server exists only to capture the
    parameter bytes the client sends.
    """

    def __init__(self) -> None:
        self.received: bytes | None = None
        self._sock = None
        self._thread: threading.Thread | None = None
        self.port = 0
        self._ready = threading.Event()

    def start(self) -> None:
        import socket

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        self._ready.wait(1.0)

    def _accept(self) -> None:
        assert self._sock is not None
        self._ready.set()
        try:
            conn, _ = self._sock.accept()
            data = conn.recv(1024)
            self.received = bytes(data)
            conn.close()
        except OSError:
            pass

    def stop(self) -> None:
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


@pytest.fixture()
def capturing_server() -> Generator[_CapturingServer, None, None]:
    server = _CapturingServer()
    server.start()
    yield server
    server.stop()


def _called_tsap(cotp_cr: bytes) -> bytes:
    """Extract the COTP called-TSAP parameter (0xC2) from a TPKT frame."""
    assert cotp_cr[0] == 3, "TPKT version"
    length = struct.unpack_from(">H", cotp_cr, 2)[0]
    pdu = cotp_cr[4:length]
    offset = 7  # LI, type, dst-ref, src-ref, class
    while offset + 2 <= len(pdu):
        code, param_len = pdu[offset], pdu[offset + 1]
        if code == 0xC2:
            return pdu[offset + 2 : offset + 2 + param_len]
        offset += 2 + param_len
    raise AssertionError("no called-TSAP parameter in the Connection Request")


class TestWireBehavior:
    """The selected TSAP is what reaches the wire."""

    def test_es_connection_type_reaches_the_wire(self, capturing_server: _CapturingServer) -> None:
        connection = S7CommPlusConnection("127.0.0.1", port=capturing_server.port, connection_type="es")
        try:
            connection._iso_conn.connect(timeout=1.0)
        except Exception:
            pass  # the capturing server closes after one read; the CR is recorded
        assert capturing_server.received is not None
        assert _called_tsap(capturing_server.received) == b"SIMATIC-ROOT-ES"

    def test_default_connection_type_reaches_the_wire(self, capturing_server: _CapturingServer) -> None:
        connection = S7CommPlusConnection("127.0.0.1", port=capturing_server.port)
        try:
            connection._iso_conn.connect(timeout=1.0)
        except Exception:
            pass
        assert capturing_server.received is not None
        assert _called_tsap(capturing_server.received) == b"SIMATIC-ROOT-HMI"


class TestEmulatorStillAcceptsDefaults:
    """The default HMI identity keeps working end to end against the emulator."""

    def test_connect_with_default(self, emulator: tuple[S7CommPlusServer, int]) -> None:
        _srv, port = emulator
        client = S7CommPlusClient()
        client.connect("127.0.0.1", port=port)
        try:
            assert client.connected
        finally:
            client.disconnect()


@pytest.fixture()
def emulator() -> Generator[tuple[S7CommPlusServer, int], None, None]:
    srv = S7CommPlusServer()
    srv.register_db(1, {"temperature": ("Real", 0)})
    srv.start(port=0)
    port = srv.port
    import time

    time.sleep(0.1)
    yield srv, port
    srv.stop()
