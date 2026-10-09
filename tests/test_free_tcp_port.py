"""Tests for the ``get_free_tcp_port`` helper the emulator tests rely on."""

import inspect
import socket
from typing import Any

import pytest

from s7commplus.server import S7CommPlusServer
from tests.conftest import get_free_tcp_port


def test_probes_the_address_the_emulator_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    # A port free on 127.0.0.1 alone can be in use on another interface, and the
    # emulator's wildcard bind then fails with "Address already in use".
    bound: list[Any] = []
    real_socket = socket.socket

    class RecordingSocket(real_socket):
        def bind(self, address: Any) -> None:
            bound.append(address)
            super().bind(address)

    monkeypatch.setattr(socket, "socket", RecordingSocket)
    get_free_tcp_port()

    emulator_host = inspect.signature(S7CommPlusServer.start).parameters["host"].default
    assert bound == [(emulator_host, 0)]


def test_emulator_starts_on_the_returned_port() -> None:
    server = S7CommPlusServer()
    port = get_free_tcp_port()
    server.start(port=port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0):
            pass
    finally:
        server.stop()
