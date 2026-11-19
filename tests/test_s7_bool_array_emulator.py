"""browse() and symbolic access of Bool arrays in a standard-access DB, through the emulator.

The emulator serves ``DB_AllTypes_Std`` as captured from an S7-1500 (see
tests/fixtures/s7_1500_db_alltypes_std.py): the type-info reply and the DB bytes as
the PLC sent them, and each symbol at the offset TIA Portal shows for it. It does not
derive offsets from the type info, so a browse() that reports the wrong offset or
access id for an element fails here.

Every Bool element of ``aBool`` and ``aBool2d`` is read by name and compared with the
bit at the offset browse() reported for it; flipping it by name must change only that
bit, and the Int members next to the arrays must keep their values.
"""

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.server import DataBlock, S7CommPlusServer

_FIXTURE = Path(__file__).parent / "fixtures" / "s7_1500_db_alltypes_std.py"
_spec = importlib.util.spec_from_file_location("s7_1500_db_alltypes_std", _FIXTURE)
assert _spec is not None and _spec.loader is not None
alltypes_std = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(alltypes_std)

DB_NUMBER = 41
TYPE_INFO_RID = 0x92000029  # the type object in the capture
BOOLS = [name for name, (_, value, _) in alltypes_std.TIA.items() if value is not None]
INTS = ["aInt[-2]", "aInt2d[0,0]", "aAfter2d"]  # declared Int; the non-Bool neighbours that must not move


def _symbols() -> dict[tuple[int, ...], tuple[str, int, int]]:
    """Each served member's LID path, type and TIA offset, from the capture's TIA table."""
    symbols = {}
    for name in BOOLS + INTS:
        offset, _, access = alltypes_std.TIA[name]
        byte, bit = (int(part) for part in offset.split("."))
        symbols[tuple(int(part, 16) for part in access.split("."))] = ("Bool" if name in BOOLS else "Int", byte, bit)
    return symbols


@pytest.fixture
def server() -> Iterator[S7CommPlusServer]:
    srv = S7CommPlusServer()
    data = bytearray(alltypes_std.RAW_OFFSET) + bytearray(alltypes_std.RAW)
    srv.register_symbolic_db(DB_NUMBER, data, TYPE_INFO_RID, alltypes_std.EXPLORE_TYPE_INFO, _symbols())
    srv.start(port=0)
    try:
        yield srv
    finally:
        srv.stop()


def _db(server: S7CommPlusServer) -> DataBlock:
    db = server.get_db(DB_NUMBER)
    assert db is not None
    return db


def _entries(variables: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    prefix = f"DB{DB_NUMBER}."
    return {v["name"].removeprefix(prefix): v for v in variables if v["name"].startswith(prefix)}


def _bit(raw: bytes, entry: dict[str, Any]) -> bool:
    return bool((raw[entry["nonopt_address"]] >> entry["nonopt_bitoffset"]) & 1)


def _changed_bits(before: bytes, after: bytes) -> dict[int, int]:
    """Per changed byte, the bits that changed."""
    return {i: a ^ b for i, (a, b) in enumerate(zip(before, after)) if a != b}


def test_served_layout_is_the_captured_one(server: S7CommPlusServer) -> None:
    """browse() over the emulator gives the offsets and access ids TIA Portal shows."""
    with S7CommPlusClient() as client:
        client.connect("127.0.0.1", port=server.port)
        entries = _entries(client.browse())
    assert {name: (f"{entries[name]['nonopt_address']}.{entries[name]['nonopt_bitoffset']}") for name in BOOLS + INTS} == {
        name: alltypes_std.TIA[name][0] for name in BOOLS + INTS
    }


def test_sync_bool_array_elements_read_and_write_their_own_bit(server: S7CommPlusServer) -> None:
    db = _db(server)
    with S7CommPlusClient() as client:
        client.connect("127.0.0.1", port=server.port)
        entries = _entries(client.browse())
        names = {name: f"DB{DB_NUMBER}.{name}" for name in BOOLS + INTS}
        raw = client.db_read(DB_NUMBER, 0, len(db.data))
        ints = {name: client.read_value(names[name]) for name in INTS}
        assert ints["aAfter2d"] == 0x7777

        for name in BOOLS:
            value = client.read_value(names[name])
            assert value is _bit(raw, entries[name]) is alltypes_std.TIA[name][1], name

            before = bytes(db.data)
            client.write_value(names[name], not value)
            assert _changed_bits(before, bytes(db.data)) == {
                entries[name]["nonopt_address"]: 1 << entries[name]["nonopt_bitoffset"]
            }
            assert client.read_value(names[name]) is (not value), name
            assert {n: client.read_value(names[n]) for n in INTS} == ints, name

            client.write_value(names[name], value)
            assert bytes(db.data) == before, name


async def test_async_bool_array_elements_read_and_write_their_own_bit(server: S7CommPlusServer) -> None:
    db = _db(server)
    async with S7CommPlusAsyncClient() as client:
        await client.connect("127.0.0.1", port=server.port)
        entries = _entries(await client.browse())
        names = {name: f"DB{DB_NUMBER}.{name}" for name in BOOLS + INTS}
        raw = await client.db_read(DB_NUMBER, 0, len(db.data))
        ints = {name: await client.read_value(names[name]) for name in INTS}
        assert ints["aAfter2d"] == 0x7777

        for name in BOOLS:
            value = await client.read_value(names[name])
            assert value is _bit(raw, entries[name]) is alltypes_std.TIA[name][1], name

            before = bytes(db.data)
            await client.write_value(names[name], not value)
            assert _changed_bits(before, bytes(db.data)) == {
                entries[name]["nonopt_address"]: 1 << entries[name]["nonopt_bitoffset"]
            }
            assert await client.read_value(names[name]) is (not value), name
            assert {n: await client.read_value(names[n]) for n in INTS} == ints, name

            await client.write_value(names[name], value)
            assert bytes(db.data) == before, name


def test_a_db_without_symbols_still_has_no_type_info() -> None:
    """Data blocks registered without symbols keep failing the LID=1 read, so browse() skips them."""
    srv = S7CommPlusServer()
    srv.register_raw_db(1, bytearray(16))
    srv.start(port=0)
    try:
        with S7CommPlusClient() as client:
            client.connect("127.0.0.1", port=srv.port)
            assert client.browse() == []
    finally:
        srv.stop()


def test_a_second_symbolic_db_must_bring_the_same_type_info() -> None:
    srv = S7CommPlusServer()
    srv.register_symbolic_db(DB_NUMBER, bytearray(976), TYPE_INFO_RID, alltypes_std.EXPLORE_TYPE_INFO, {})
    with pytest.raises(ValueError, match="different type-info reply"):
        srv.register_symbolic_db(42, bytearray(4), TYPE_INFO_RID, b"\x00", {})
    with pytest.raises(ValueError, match="Unknown type name"):
        srv.register_symbolic_db(43, bytearray(4), TYPE_INFO_RID, alltypes_std.EXPLORE_TYPE_INFO, {(9,): ("Bogus", 0, 0)})
