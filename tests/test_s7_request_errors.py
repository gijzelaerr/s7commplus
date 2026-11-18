"""Failed requests raise ``S7RequestError``, which is both an ``S7Error`` and a ``RuntimeError``."""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import s7commplus
from s7commplus import AsyncClient, Client, S7Error, S7RequestError, Server
from s7commplus.client import _parse_write_response

PACKAGE = Path(s7commplus.__file__).parent


@pytest.fixture()
def emulator() -> Iterator[int]:
    server = Server()
    server.register_raw_db(1, bytearray(4))
    server.start(port=0)
    time.sleep(0.1)
    yield server.port
    server.stop()


@pytest.mark.parametrize("module", ["client.py", "async_client.py"])
def test_the_clients_raise_no_bare_runtime_error(module: str) -> None:
    source = (PACKAGE / module).read_text(encoding="utf-8")
    assert re.findall(r"raise RuntimeError\(", source) == []


def test_s7_request_error_is_an_s7_error_and_a_runtime_error() -> None:
    assert issubclass(S7RequestError, S7Error)
    assert issubclass(S7RequestError, RuntimeError)


def test_the_error_classes_are_exported_from_the_package_root() -> None:
    from s7commplus import error

    exported = {name for name in s7commplus.__all__ if name.startswith("S7") and name.endswith("Error")}
    for name in exported:
        assert getattr(s7commplus, name) is getattr(error, name)
    assert {"S7Error", "S7ConnectionError", "S7TimeoutError", "S7ReturnValueError", "S7RequestError"} <= exported


def test_sync_read_of_a_missing_db_raises_s7_request_error(emulator: int) -> None:
    with Client() as client:
        client.connect("127.0.0.1", port=emulator)
        with pytest.raises(S7RequestError, match="^Read failed: PLC returned error for item$"):
            client.db_read(2, 0, 4)
        assert client.db_read(1, 0, 4) == b"\x00" * 4


async def test_async_read_of_a_missing_db_raises_s7_request_error(emulator: int) -> None:
    async with AsyncClient() as client:
        await client.connect("127.0.0.1", port=emulator)
        with pytest.raises(S7RequestError, match="^Read failed: PLC returned error for item$"):
            await client.db_read(2, 0, 4)
        assert await client.db_read(1, 0, 4) == b"\x00" * 4


def test_a_refused_write_item_raises_s7_request_error_with_the_same_message() -> None:
    # The S7-1500 reply from #193: ReturnValue 19 (partial error) naming item 1.
    reply = bytes.fromhex("908b90808083ca801301c082b19080c5edfffe00")
    with pytest.raises(S7RequestError, match=f"^Write failed: item 1: error {0x800989001176FFFE}$"):
        _parse_write_response(reply)


def test_the_api_page_lists_exactly_the_exported_error_classes() -> None:
    # docs/api.rst says every class it lists is importable from s7commplus.
    api = (PACKAGE.parent / "docs" / "api.rst").read_text(encoding="utf-8")
    match = re.search(r"automodule:: s7commplus\.error\n   :members: (.*)", api)
    assert match is not None
    listed = set(match.group(1).split(", "))
    exported = {name for name in s7commplus.__all__ if name.startswith("S7") and name.endswith("Error")}
    assert listed == exported
