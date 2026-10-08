"""Typed tag values: per-type conversion, struct/array assembly, and the read_value/write_value API.

Known-answer vectors are the raw bytes PLCSIM Advanced (CPU 1511, FW V2.9) returned for the
"Types DB" test block (one member per datatype) and the layouts it accepted on write.
"""

from __future__ import annotations

import datetime as dt
import inspect
import math
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus import values
from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.catalog import SymbolCatalog, SymbolicTag, TagResult
from s7commplus.client import _AUTO_REFRESH_MIN_INTERVAL, S7CommPlusClient
from s7commplus.codec import encode_pvalue_blob
from s7commplus.typeinfo import Softdatatype as T
from s7commplus.vlq import decode_uint32_vlq, encode_uint32_vlq, encode_uint64_vlq

UTC_PLUS_2 = dt.timezone(dt.timedelta(hours=2))

# --- Per-type conversion -----------------------------------------------------------------

PLCSIM_READS = [
    (T.BBOOL, "01", True),
    (T.BYTE, "12", 0x12),
    (T.WORD, "1234", 0x1234),
    (T.DWORD, "12345678", 0x12345678),
    (T.LWORD, "123456789abcdef0", 0x123456789ABCDEF0),
    (T.SINT, "fb", -5),
    (T.INT, "fb2e", -1234),
    (T.DINT, "fffe1dc0", -123456),
    (T.LINT, "fffffee08e04fb35", -1234567890123),
    (T.USINT, "c8", 200),
    (T.UINT, "ea60", 60000),
    (T.UDINT, "ee6b2800", 4000000000),
    (T.ULINT, "00000b3a73ce2ff2", 12345678901234),
    (T.REAL, "40600000", 3.5),
    (T.LREAL, "4002000000000000", 2.25),
    (T.CHAR, "41", "A"),
    (T.WCHAR, "0020", " "),
    (T.STRING, "0a0361626300000000000000", "abc"),
    (T.STRING, "fe0568656c6c6f" + "00" * 249, "hello"),
    (T.WSTRING, "00fe0000" + "00" * 508, ""),
    (T.TIME, "000003e8", dt.timedelta(seconds=1)),
    (T.LTIME, "0000000000000000", dt.timedelta(0)),
    (T.DATE, "346f", dt.date(2026, 10, 2)),
    (T.TIMEOFDAY, "02b32980", dt.time(12, 34, 56)),
    (T.LTOD, "0000000000000000", dt.time(0)),
    (T.DATEANDTIME, "9001010000000002", dt.datetime(1990, 1, 1)),
    (T.LDT, "0000000000000000", dt.datetime(1970, 1, 1)),
    (T.S5TIME, "0200", dt.timedelta(seconds=2)),
]


@pytest.mark.parametrize(("softdatatype", "raw", "expected"), PLCSIM_READS)
def test_decode_plcsim_values(softdatatype: T, raw: str, expected: Any) -> None:
    assert values.decode(softdatatype, bytes.fromhex(raw)) == expected


@pytest.mark.parametrize(
    ("softdatatype", "raw", "expected"),
    [
        (T.WSTRING, "00fe0003007700e40068", "wäh"),  # written by the client, read back from PLCSIM
        (T.DATEANDTIME, "2610021234561237", dt.datetime(2026, 10, 2, 12, 34, 56, 123000)),
        (T.LDT, "17979cfe3d85cd15", dt.datetime(2023, 11, 14, 22, 13, 20, 123456)),
        (T.LTIME, "0000000059682f01", dt.timedelta(seconds=1, microseconds=500000)),  # 1.500000001 s, truncated
        (T.LTIME, "fffffffffffffc17", dt.timedelta(microseconds=-1)),  # -1001 ns truncates toward zero
        (T.TIME, "fffff63c", dt.timedelta(milliseconds=-2500)),
        (T.S5TIME, "1250", dt.timedelta(seconds=25)),  # base 100 ms x 250
        (T.S5TIME, "3999", dt.timedelta(seconds=9990)),
        (T.LTOD, "0000034630b8a001", dt.time(1, 0, 0, 0)),
    ],
)
def test_decode_written_values(softdatatype: T, raw: str, expected: Any) -> None:
    assert values.decode(softdatatype, bytes.fromhex(raw)) == expected


@pytest.mark.parametrize(
    ("softdatatype", "raw"),
    [
        (T.INT, "01"),  # truncated
        (T.BBOOL, ""),
        (T.STRING, "0a"),  # header cut short
        (T.STRING, "020361626300"),  # current length above the maximum
        (T.STRING, "0a05616263"),  # fewer characters than the length says
        (T.WSTRING, "0001"),
        (T.WSTRING, "00020002d800"),  # characters cut short
        (T.WSTRING, "00010001d800"),  # a lone surrogate
        (T.WCHAR, "dc00"),
        (T.DATE, "346f00"),
        (T.TIMEOFDAY, "05265c00"),  # 24:00:00
        (T.LTOD, "00004e94914f0000"),  # one day of nanoseconds
        (T.DATEANDTIME, "9a01010000000002"),  # not BCD
        (T.DATEANDTIME, "2613010000000002"),  # month 13
        (T.DATEANDTIME, "26010100000000a2"),  # millisecond nibble not BCD
        (T.S5TIME, "00fa"),  # not BCD
        (T.S5TIME, "0a00"),  # hundreds nibble above 9
        (T.STRING, "ff0161"),  # declared length above 254
        (T.WSTRING, "3fff00010061"),  # declared length above 16382
        (T.DATE, "ff63"),  # 2169-01-01: after D#2168-12-31
        (T.LDT, "8000000000000000"),  # before 1970 (LDT is a signed nanosecond count)
        (T.DTL, "07b2010105000000"),  # no scalar conversion: DTL arrives as members
    ],
)
def test_decode_keeps_bytes_it_cannot_interpret(softdatatype: T, raw: str) -> None:
    assert values.decode(softdatatype, bytes.fromhex(raw)) == bytes.fromhex(raw)


@pytest.mark.parametrize(("softdatatype", "raw", "expected"), PLCSIM_READS)
def test_encode_round_trips_plcsim_values(softdatatype: T, raw: str, expected: Any) -> None:
    string_length = (len(raw) // 2 - 2) if softdatatype is T.STRING else 254
    encoded = values.encode(softdatatype, expected, string_length=string_length)
    assert values.decode(softdatatype, encoded) == expected
    if softdatatype not in (T.WCHAR,):
        assert encoded == bytes.fromhex(raw)


@pytest.mark.parametrize(
    ("softdatatype", "value", "length", "raw"),
    [
        (T.STRING, "xyz", 10, "0a0378797a" + "00" * 7),  # padded to the declared length
        (T.STRING, "", 2, "02000000"),
        (T.WSTRING, "wäh", 4, "00040003007700e40068" + "0000"),
        (T.CHAR, "Z", 0, "5a"),
        (T.WCHAR, "Ω", 0, "03a9"),
        (T.DATE, dt.date(2026, 10, 3), 0, "3470"),
        (T.TIMEOFDAY, dt.time(1), 0, "0036ee80"),
        (T.TIMEOFDAY, 1, 0, "00000001"),
        (T.TIME, dt.timedelta(milliseconds=-2500), 0, "fffff63c"),
        (T.TIME, 1000, 0, "000003e8"),
        (T.LTIME, dt.timedelta(seconds=1, microseconds=500000), 0, "0000000059682f00"),
        (T.LTIME, 1_500_000_001, 0, "0000000059682f01"),
        (T.LTOD, dt.time(1, 0, 0, 1), 0, "0000034630b8a3e8"),
        (T.LDT, dt.datetime(2023, 11, 14, 22, 13, 20, 123456), 0, "17979cfe3d85ca00"),  # 789 ns below PLCSIM's
        (T.LDT, dt.datetime(2262, 4, 11, 23, 47, 16, 854775), 0, "7ffffffffffffcd8"),  # LDT's last microsecond
        (T.LDT, 2**63 - 1, 0, "7fffffffffffffff"),
        (T.DATE, dt.date(2168, 12, 31), 0, "ff62"),  # D#2168-12-31, DATE's last day
        (T.DATEANDTIME, dt.datetime(2026, 10, 2, 12, 34, 56, 123000), 0, "2610021234561236"),  # a Friday
        (T.DATEANDTIME, dt.datetime(1990, 1, 1), 0, "9001010000000002"),  # a Monday
        (T.S5TIME, dt.timedelta(seconds=25), 0, "1250"),  # 100 ms base: the 10 ms base tops out at 9.99 s
        (T.S5TIME, dt.timedelta(seconds=9990), 0, "3999"),
        (T.S5TIME, 0, 0, "0000"),
        (T.BBOOL, 1, 0, "01"),
        (T.BBOOL, 0, 0, "00"),
        (T.BBOOL, True, 0, "01"),
        (T.REAL, 2, 0, "40000000"),
        (T.REAL, math.inf, 0, "7f800000"),  # IEEE 754 values a REAL can hold
        (T.REAL, -math.inf, 0, "ff800000"),
        (T.LREAL, math.inf, 0, "7ff0000000000000"),
    ],
)
def test_encode_known_answers(softdatatype: T, value: Any, length: int, raw: str) -> None:
    assert values.encode(softdatatype, value, string_length=length) == bytes.fromhex(raw)


@pytest.mark.parametrize(
    ("softdatatype", "value", "error"),
    [
        (T.INT, 32768, ValueError),
        (T.USINT, -1, ValueError),
        (T.INT, 1.5, TypeError),
        (T.INT, True, TypeError),
        (T.REAL, "1", TypeError),
        (T.REAL, 1e40, ValueError),  # finite but beyond a REAL
        (T.REAL, 2**200, ValueError),
        (T.LREAL, 10**400, ValueError),
        (T.BBOOL, "yes", TypeError),
        (T.BBOOL, 5, ValueError),
        (T.BBOOL, -1, ValueError),
        (T.CHAR, "ab", TypeError),
        (T.CHAR, "€", ValueError),
        (T.WCHAR, "😀", ValueError),  # outside the BMP: two UTF-16 units
        (T.STRING, "x" * 11, ValueError),
        (T.STRING, "温", ValueError),
        (T.STRING, b"x", TypeError),
        (T.DATE, dt.datetime(2026, 1, 1), TypeError),  # a datetime would silently lose its time
        (T.DATE, dt.date(1989, 12, 31), ValueError),
        (T.DATE, dt.date(2169, 1, 1), ValueError),
        (T.TIME, dt.timedelta(microseconds=1500), ValueError),
        (T.TIME, 2**31, ValueError),
        (T.TIME, "1s", TypeError),
        (T.TIMEOFDAY, dt.time(0, 0, 0, 1), ValueError),
        (T.TIMEOFDAY, 86_400_000, ValueError),
        (T.TIMEOFDAY, dt.time(12, tzinfo=UTC_PLUS_2), ValueError),  # no PLC type stores a time zone
        (T.LTOD, -1, ValueError),
        (T.LTOD, dt.time(12, tzinfo=dt.timezone.utc), ValueError),
        (T.LDT, dt.date(2026, 1, 1), TypeError),
        (T.LDT, dt.datetime(1969, 12, 31), ValueError),
        (T.LDT, dt.datetime(2262, 4, 11, 23, 47, 16, 854776), ValueError),
        (T.LDT, 2**63, ValueError),
        (T.LDT, -1, ValueError),
        (T.LDT, dt.datetime(2026, 1, 1, 12, tzinfo=UTC_PLUS_2), ValueError),
        (T.DATEANDTIME, dt.datetime(2090, 1, 1), ValueError),
        (T.DATEANDTIME, dt.datetime(2026, 1, 1, 0, 0, 0, 1), ValueError),
        (T.DATEANDTIME, dt.datetime(2026, 1, 1, 12, tzinfo=UTC_PLUS_2), ValueError),
        (T.S5TIME, dt.timedelta(seconds=10000), ValueError),
        (T.S5TIME, 15, ValueError),  # not a multiple of 10 ms
        (T.DTL, 1, TypeError),
    ],
)
def test_encode_rejects_values_the_type_cannot_hold(softdatatype: T, value: Any, error: type[Exception]) -> None:
    with pytest.raises(error):
        values.encode(softdatatype, value, string_length=10)


def test_encode_names_the_type_of_a_value_it_cannot_hold() -> None:
    with pytest.raises(ValueError, match=r"1e\+40 does not fit a REAL"):
        values.encode(T.REAL, 1e40)
    with pytest.raises(ValueError, match="DATE_AND_TIME stores no time zone"):
        values.encode(T.DATEANDTIME, dt.datetime(2026, 1, 1, 12, tzinfo=UTC_PLUS_2))


def test_encode_keeps_nan() -> None:
    assert math.isnan(values.decode(T.REAL, values.encode(T.REAL, math.nan)))
    assert math.isnan(values.decode(T.LREAL, values.encode(T.LREAL, math.nan)))


def test_encode_takes_the_longest_declared_strings() -> None:
    assert values.encode(T.STRING, "", string_length=254) == bytes.fromhex("fe00") + bytes(254)
    longest = values.encode(T.WSTRING, "x" * 16382, string_length=16382)
    assert longest[:6] == bytes.fromhex("3ffe3ffe0078") and len(longest) == 4 + 2 * 16382
    assert values.decode(T.WSTRING, longest) == "x" * 16382


@pytest.mark.parametrize(
    ("softdatatype", "string_length"),
    [(T.STRING, 255), (T.STRING, -1), (T.WSTRING, 16383)],
)
def test_encode_rejects_a_declared_string_length_out_of_range(softdatatype: T, string_length: int) -> None:
    # The declared length comes from the PLC's catalog: it is checked, not trusted.
    with pytest.raises(ValueError, match="declared with 1 to"):
        values.encode(softdatatype, "a", string_length=string_length)


@pytest.mark.parametrize("softdatatype", [T.STRING, T.WSTRING])
def test_encode_refuses_a_string_of_unknown_declared_length(softdatatype: T) -> None:
    # The header and padding follow the declared length; a guess would not match a shorter
    # declaration (PLCSIM refused a STRING[10] written with a maximum length of 254).
    with pytest.raises(ValueError, match=r"declared length, which is unknown \(string_length 0\)"):
        values.encode(softdatatype, "a")
    with pytest.raises(ValueError, match="unknown"):
        values.encode(softdatatype, "", string_length=0)


def _tag(name: str, softdatatype: T, *, string_length: int = 0, dimensions: Any = ()) -> SymbolicTag:
    return SymbolCatalog.from_browse(
        [
            {
                "name": name,
                "access_sequence": "8A0E0004.1",
                "data_type": softdatatype.name,
                "string_length": string_length,
                "array_dimensions": dimensions,
            }
        ]
    ).resolve(name)


def test_symbolic_tag_decodes_array_elements_and_strings() -> None:
    # Element tags carry their array's dimensions; they are still scalars.
    assert _tag("T.a[1]", T.INT, dimensions=[(0, 2)]).decode_value(b"\x00\x02") == 2
    assert _tag("s", T.STRING, string_length=4).decode_value(bytes.fromhex("040268690000")) == "hi"


def test_symbolic_tag_encodes_with_its_declared_string_length() -> None:
    assert _tag("s", T.STRING, string_length=4).encode_value("hi") == bytes.fromhex("040268690000")
    assert _tag("w", T.WSTRING, string_length=2).encode_value("ä") == bytes.fromhex("0002000100e40000")
    with pytest.raises(ValueError, match="declared with 1 to 254 characters, got 300"):
        _tag("s", T.STRING, string_length=300).encode_value("x")
    for softdatatype in (T.STRING, T.WSTRING):  # no declared length in the catalog
        with pytest.raises(ValueError, match="unknown"):
            _tag("s", softdatatype).encode_value("x")


# --- Structs and arrays ------------------------------------------------------------------


def test_member_path() -> None:
    assert values._member_path("DB.s", "DB.s.arr[1].x") == ("arr", (1,), "x")
    assert values._member_path("DB.a", "DB.a[-2]") == ((-2,),)
    assert values._member_path("DB.m", "DB.m[0,2]") == ((0, 2),)
    with pytest.raises(ValueError):
        values._member_path("DB.s", "DB.s]x")
    assert values._is_member("DB.s", "DB.s.a") and values._is_member("DB.s", "DB.s[1]")
    assert not values._is_member("DB.s", "DB.sx") and not values._is_member("DB.s", "DB.s")


def test_assemble_arrays_structs_and_dtl() -> None:
    leaves = [
        ("T.arr2d[0,0]", 1),
        ("T.arr2d[0,1]", 2),
        ("T.arr2d[1,0]", 3),
        ("T.arr2d[1,1]", 4),
    ]
    assert values.assemble("T.arr2d", leaves) == [[1, 2], [3, 4]]
    assert values.assemble("T.neg", [("T.neg[0]", "b"), ("T.neg[-1]", "a")]) == ["a", "b"]
    udts = [("T.u[1].a", 11), ("T.u[0].a", 0), ("T.u[0].b.c", 0.5), ("T.u[1].b.c", 1.5)]
    assert values.assemble("T.u", udts) == [{"a": 0, "b": {"c": 0.5}}, {"a": 11, "b": {"c": 1.5}}]
    dtl = list(zip(("T.d." + m for m in values._DTL_MEMBERS), (2026, 10, 8, 5, 7, 48, 1, 250_000_999)))
    assert values.assemble("T.d", dtl) == dt.datetime(2026, 10, 8, 7, 48, 1, 250000)
    invalid = list(zip(("T.d." + m for m in values._DTL_MEMBERS), (2026, 13, 8, 5, 7, 48, 1, 0)))
    assert values.assemble("T.d", invalid)["MONTH"] == 13  # not a date: stays a dict


def test_assemble_rejects_inconsistent_leaves() -> None:
    with pytest.raises(ValueError):
        values.assemble("T.s", [("T.s.a", 1), ("T.s.a.b", 2)])
    with pytest.raises(ValueError):
        values.assemble("T.s", [("T.s", 1)])


ARRAY_NAMES = [f"T.m[{i},{j}]" for i in range(2) for j in range(3)]


def test_split_inverts_assemble() -> None:
    names = ["T.u[0].a", "T.u[0].b.c", "T.u[1].a", "T.u[1].b.c"]
    assert values.split("T.u", [{"a": 1, "b": {"c": 0.5}}, {"a": 2, "b": {"c": 1.5}}], names) == {
        "T.u[0].a": 1,
        "T.u[0].b.c": 0.5,
        "T.u[1].a": 2,
        "T.u[1].b.c": 1.5,
    }
    assert values.split("T.m", [[1, 2, 3], [4, 5, 6]], ARRAY_NAMES) == dict(zip(ARRAY_NAMES, range(1, 7)))
    assert values.split("T.n", [7, 8], ["T.n[-1]", "T.n[0]"]) == {"T.n[-1]": 7, "T.n[0]": 8}


def test_split_accepts_partial_dicts_and_index_keys() -> None:
    names = ["T.s.a", "T.s.b.c", "T.s.f[0]", "T.s.f[1]"]
    assert values.split("T.s", {"b": {"c": 1.0}}, names) == {"T.s.b.c": 1.0}
    assert values.split("T.s", {"f": {1: True}}, names) == {"T.s.f[1]": True}
    assert values.split("T.m", {(1, 2): 9}, ARRAY_NAMES) == {"T.m[1,2]": 9}


def test_split_takes_a_datetime_for_a_dtl() -> None:
    names = ["T.d." + member for member in values._DTL_MEMBERS]
    split = values.split("T.d", dt.datetime(2026, 10, 4, 7, 48, 1, 250000), names)  # a Sunday
    assert split["T.d.WEEKDAY"] == 1 and split["T.d.NANOSECOND"] == 250_000_000 and split["T.d.YEAR"] == 2026


DTL_NAMES = ["T.s.stamp." + member for member in values._DTL_MEMBERS] + ["T.s.t.a", "T.s.t.b"]


@pytest.mark.parametrize(
    "value",
    [
        {"t": dt.datetime(2026, 10, 8, 7, 48)},
        # Regression: the member dict built for "stamp" was a temporary checked by id();
        # a later one could reuse its id, skip the check and silently drop "t".
        {"stamp": dt.datetime(2026, 10, 8, 7, 48), "t": dt.datetime(2026, 10, 8, 7, 48)},
        {"t": dt.datetime(2026, 10, 8, 7, 48), "stamp": dt.datetime(2026, 10, 8, 7, 48)},
    ],
)
def test_split_takes_a_datetime_only_for_a_dtl(value: dict[str, Any]) -> None:
    with pytest.raises(TypeError, match=r"T\.s\.t is a struct; give a dict, got datetime"):
        values.split("T.s", value, DTL_NAMES)


@pytest.mark.parametrize(
    ("when", "match"),
    [
        (dt.datetime(2026, 10, 8, 12, tzinfo=UTC_PLUS_2), "DTL stores no time zone"),
        (dt.datetime(1969, 12, 31, 23, 59), "DTL holds 1970-01-01 to 2262-04-11"),
        (dt.datetime(2262, 4, 11, 23, 47, 16, 854776), "DTL holds 1970-01-01 to 2262-04-11"),
    ],
)
def test_split_rejects_a_dtl_it_cannot_hold(when: dt.datetime, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        values.split("T.s", {"stamp": when}, DTL_NAMES)


@pytest.mark.parametrize(
    ("value", "error", "match"),
    [
        ({"a": 1, "typo": 2}, ValueError, "no member or element 'typo'"),
        ({"f": [True]}, ValueError, "has 2 elements, got 1"),
        ({"f": True}, TypeError, "is an array"),
        ([1, 2], TypeError, "is a struct"),
    ],
)
def test_split_rejects_mismatched_values(value: Any, error: type[Exception], match: str) -> None:
    with pytest.raises(error, match=match):
        values.split("T.s", value, ["T.s.a", "T.s.f[0]", "T.s.f[1]"])


def test_split_rejects_a_wrong_multi_dimensional_shape() -> None:
    with pytest.raises(ValueError, match="dimension 2 has 3 elements"):
        values.split("T.m", [[1, 2], [3, 4]], ARRAY_NAMES)


# --- read_value / write_value ------------------------------------------------------------

BROWSE = [
    {"name": "T.i", "access_sequence": "8A0E0004.1", "data_type": "INT"},
    {"name": "T.s", "access_sequence": "8A0E0004.2", "data_type": "STRING", "string_length": 4},
    {"name": "T.d", "access_sequence": "8A0E0004.3", "data_type": "DATE"},
    {"name": "T.a[0]", "access_sequence": "8A0E0004.4.0", "data_type": "INT", "array_dimensions": [(0, 2)]},
    {"name": "T.a[1]", "access_sequence": "8A0E0004.4.1", "data_type": "INT", "array_dimensions": [(0, 2)]},
    {"name": "T.u.x", "access_sequence": "8A0E0004.5.1", "data_type": "REAL"},
    {"name": "T.u.y", "access_sequence": "8A0E0004.5.2", "data_type": "BBOOL"},
]

RAW = {
    "T.i": bytes.fromhex("fb2e"),
    "T.s": bytes.fromhex("0402686900000000")[:6],
    "T.d": bytes.fromhex("346f"),
    "T.a[0]": b"\x00\x01",
    "T.a[1]": b"\x00\x02",
    "T.u.x": bytes.fromhex("40600000"),
    "T.u.y": b"\x01",
}


def _results(catalog: SymbolCatalog, names: list[str]) -> list[TagResult]:
    return [TagResult(tag=catalog.resolve(name), value=RAW[name]) for name in names]


def _sync_client() -> tuple[S7CommPlusClient, SymbolCatalog]:
    client = S7CommPlusClient()
    client._connection = MagicMock()
    catalog = SymbolCatalog.from_browse(BROWSE)
    client._symbol_catalog = catalog
    client.read_tags = MagicMock(side_effect=lambda names: _results(catalog, list(names)))  # type: ignore[method-assign]
    client.write_tags = MagicMock(side_effect=lambda raw: [TagResult(tag=catalog.resolve(n)) for n in raw])  # type: ignore[method-assign]
    return client, catalog


def test_read_value_decodes_leaves_and_containers_in_one_request() -> None:
    client, _ = _sync_client()

    assert client.read_value("T.i") == -1234
    assert client.read_values(["T.s", "T.d", "T.a", "T.u"]) == ["hi", dt.date(2026, 10, 2), [1, 2], {"x": 3.5, "y": True}]
    assert client.read_tags.call_args.args[0] == ["T.s", "T.d", "T.a[0]", "T.a[1]", "T.u.x", "T.u.y"]


def test_read_value_unknown_name_raises_key_error() -> None:
    client, _ = _sync_client()
    with pytest.raises(KeyError):
        client.read_value("T.nope")
    with pytest.raises(KeyError):
        client.read_value("T.u.x.y")


def test_read_value_reports_failed_items() -> None:
    client, catalog = _sync_client()
    client.read_tags.side_effect = lambda names: [TagResult(tag=catalog.resolve(n), error=RuntimeError("boom")) for n in names]
    with pytest.raises(RuntimeError, match=r"2 of 2 reads failed: 'T.a\[0\]', 'T.a\[1\]'"):
        client.read_value("T.a")


def test_write_values_encodes_every_leaf_into_one_request() -> None:
    client, _ = _sync_client()

    client.write_values({"T.i": -1234, "T.s": "hi", "T.a": [1, 2], "T.u": {"y": False}})

    (raw,) = client.write_tags.call_args.args
    assert raw == {
        "T.i": bytes.fromhex("fb2e"),
        "T.s": bytes.fromhex("040268690000"),
        "T.a[0]": b"\x00\x01",
        "T.a[1]": b"\x00\x02",
        "T.u.y": b"\x00",
    }


def test_write_value_names_the_leaf_in_a_conversion_error() -> None:
    client, _ = _sync_client()
    with pytest.raises(ValueError, match=r"'T.s': STRING\[4\] holds at most 4 characters"):
        client.write_value("T.s", "hello")
    with pytest.raises(TypeError, match="'T.u.x': REAL takes a float"):
        client.write_value("T.u", {"x": "1"})
    with pytest.raises(ValueError, match=r"'T.u.x': 1e\+40 does not fit a REAL"):
        client.write_value("T.u", {"x": 1e40})
    client.write_tags.assert_not_called()


def test_write_value_checks_the_catalog_string_length_before_sending() -> None:
    client, _ = _sync_client()
    client._symbol_catalog = SymbolCatalog.from_browse(
        [{"name": "T.s", "access_sequence": "8A0E0004.2", "data_type": "STRING", "string_length": 300}]
    )
    with pytest.raises(ValueError, match="'T.s': A STRING is declared with 1 to 254 characters, got 300"):
        client.write_value("T.s", "x")
    client.write_tags.assert_not_called()


def test_write_values_rejects_a_leaf_given_twice_and_empty_writes() -> None:
    client, _ = _sync_client()
    with pytest.raises(ValueError, match="written twice"):
        client.write_values({"T.u": {"x": 1.0}, "T.u.x": 2.0})
    with pytest.raises(ValueError, match="Nothing to write"):
        client.write_value("T.u", {})


def test_write_value_reports_rejected_items() -> None:
    client, catalog = _sync_client()
    client.write_tags.side_effect = lambda raw: [TagResult(tag=catalog.resolve(n), error=RuntimeError("PLC error")) for n in raw]
    with pytest.raises(RuntimeError, match="1 of 1 writes failed: 'T.i'"):
        client.write_value("T.i", 5)


@pytest.mark.asyncio
async def test_async_read_and_write_values() -> None:
    client = S7CommPlusAsyncClient()
    catalog = SymbolCatalog.from_browse(BROWSE)
    client._symbol_catalog = catalog
    client.read_tags = AsyncMock(side_effect=lambda names: _results(catalog, list(names)))  # type: ignore[method-assign]
    client.write_tags = AsyncMock(side_effect=lambda raw: [TagResult(tag=catalog.resolve(n)) for n in raw])  # type: ignore[method-assign]

    assert await client.read_value("T.u") == {"x": 3.5, "y": True}
    assert await client.read_values(["T.i", "T.a"]) == [-1234, [1, 2]]
    await client.write_value("T.d", dt.date(2026, 10, 3))
    assert client.write_tags.await_args.args[0] == {"T.d": bytes.fromhex("3470")}
    with pytest.raises(KeyError):
        await client.read_value("T.nope")


def _read_answer(raw_values: list[bytes]) -> bytes:
    """A GetMultiVariables answer with every item read."""
    answer = encode_uint64_vlq(0)
    for number, raw in enumerate(raw_values, 1):
        answer += encode_uint32_vlq(number) + encode_pvalue_blob(raw)
    return answer + b"\x00\x00"


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_values_of_a_large_array_are_split_like_any_batch(asynchronous: bool) -> None:
    # The leaves of one array are one batch, which read_tags/write_tags split per request.
    browse = [
        {"name": f"T.a[{index}]", "access_sequence": f"8A0E0004.4.{index}", "data_type": "INT", "array_dimensions": [(0, 5)]}
        for index in range(5)
    ]
    write_answer = encode_uint64_vlq(0) + b"\x00"
    answers = [
        _read_answer([b"\x00\x01", b"\x00\x02"]),
        _read_answer([b"\x00\x03", b"\x00\x04"]),
        _read_answer([b"\x00\x05"]),
        *[write_answer] * 3,
    ]
    send: MagicMock
    if asynchronous:
        async_client = S7CommPlusAsyncClient()
        async_client._connected = True
        async_client._send_request = send = AsyncMock(side_effect=answers)  # type: ignore[method-assign]
        async_client._symbol_catalog = SymbolCatalog.from_browse(browse)
        async_client.max_items_per_request = 2
        assert await async_client.read_value("T.a") == [1, 2, 3, 4, 5]
        await async_client.write_value("T.a", [5, 4, 3, 2, 1])
    else:
        client = S7CommPlusClient()
        client._connection = MagicMock(
            object_qualifier_version=0, requires_substreamed=False, _with_integrity_id=True, _session_key=None
        )
        send = client._connection.send_request
        send.side_effect = answers
        client._symbol_catalog = SymbolCatalog.from_browse(browse)
        client.max_items_per_request = 2
        assert client.read_value("T.a") == [1, 2, 3, 4, 5]
        client.write_value("T.a", [5, 4, 3, 2, 1])

    payloads = [call.args[1] for call in send.call_args_list]
    assert [decode_uint32_vlq(payload, 4)[0] for payload in payloads] == [2, 2, 1, 2, 2, 1]
    assert bytes.fromhex("01000700050200070004") in payloads[3]  # item 1 = 5, item 2 = 4, as INTs


# --- Unknown names with auto_refresh_tags ------------------------------------------------

GROWN = [*BROWSE, {"name": "T.new", "access_sequence": "8A0E0004.9", "data_type": "INT"}]
GROWN_RAW = {**RAW, "T.new": b"\x00\x63"}

kinds = pytest.mark.parametrize("asynchronous", [False, True])


async def _call(result: Any) -> Any:
    return await result if inspect.isawaitable(result) else result


def _refreshing_client(asynchronous: bool, monkeypatch: pytest.MonkeyPatch, *, changed: bool = True) -> Any:
    """A client with BROWSE cached; its program-change check finds GROWN when ``changed``."""
    client: S7CommPlusClient | S7CommPlusAsyncClient = S7CommPlusAsyncClient() if asynchronous else S7CommPlusClient()
    client._symbol_catalog = SymbolCatalog.from_browse(BROWSE)

    def catalog() -> SymbolCatalog:
        assert client._symbol_catalog is not None
        return client._symbol_catalog

    def check() -> bool:
        if changed:
            client._symbol_catalog = SymbolCatalog.from_browse(GROWN)
        return changed

    mock = AsyncMock if asynchronous else MagicMock
    monkeypatch.setattr(
        client,
        "read_tags",
        mock(side_effect=lambda names: [TagResult(tag=catalog().resolve(n), value=GROWN_RAW[n]) for n in names]),
    )
    monkeypatch.setattr(client, "write_tags", mock(side_effect=lambda raw: [TagResult(tag=catalog().resolve(n)) for n in raw]))
    monkeypatch.setattr(client, "refresh_caches_if_program_changed", mock(side_effect=check))
    return client


@kinds
async def test_read_value_of_an_unknown_name_reloads_stale_tags_once(asynchronous: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _refreshing_client(asynchronous, monkeypatch)
    check = client.refresh_caches_if_program_changed
    with pytest.raises(KeyError):
        await _call(client.read_value("T.new"))  # auto_refresh_tags is off by default
    check.assert_not_called()

    client.auto_refresh_tags = True
    assert await _call(client.read_value("T.new")) == 99
    assert check.call_count == 1


@kinds
async def test_write_value_of_an_unknown_name_reloads_stale_tags_once(
    asynchronous: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _refreshing_client(asynchronous, monkeypatch)
    client.auto_refresh_tags = True

    await _call(client.write_values({"T.i": 1, "T.new": 5}))

    assert client.write_tags.call_args.args[0] == {"T.i": b"\x00\x01", "T.new": b"\x00\x05"}
    assert client.refresh_caches_if_program_changed.call_count == 1


@kinds
async def test_value_lookups_honour_the_auto_refresh_interval(asynchronous: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    # A misspelt name must not cost a program-change check on every poll.
    client = _refreshing_client(asynchronous, monkeypatch, changed=False)
    client.auto_refresh_tags = True
    check = client.refresh_caches_if_program_changed

    with pytest.raises(KeyError):
        await _call(client.read_value("T.typo"))
    with pytest.raises(KeyError):
        await _call(client.write_value("T.typo", 1))
    assert check.call_count == 1  # the second lookup came within the interval

    assert client._last_auto_refresh_check is not None
    client._last_auto_refresh_check -= _AUTO_REFRESH_MIN_INTERVAL  # the interval has passed
    with pytest.raises(KeyError):
        await _call(client.read_values(["T.i", "T.typo"]))
    assert check.call_count == 2
    client.read_tags.assert_not_called()
    client.write_tags.assert_not_called()


@kinds
async def test_a_conversion_error_does_not_reload_tags(asynchronous: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    # Only the catalog lookup is retried after a check; encoding errors are the caller's.
    client = _refreshing_client(asynchronous, monkeypatch)
    client.auto_refresh_tags = True

    with pytest.raises(TypeError, match="'T.i': INT takes an int"):
        await _call(client.write_value("T.i", "x"))
    with pytest.raises(ValueError, match="no member or element 'typo'"):
        await _call(client.write_value("T.u", {"typo": 1}))

    client.refresh_caches_if_program_changed.assert_not_called()
    client.write_tags.assert_not_called()


@kinds
async def test_no_check_when_the_value_call_browsed_the_catalog(asynchronous: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _refreshing_client(asynchronous, monkeypatch)
    client.auto_refresh_tags = True
    client._symbol_catalog = None
    fresh = SymbolCatalog.from_browse(BROWSE)

    def browse() -> SymbolCatalog:
        client._symbol_catalog = fresh
        return fresh

    monkeypatch.setattr(client, "refresh_tag_catalog", (AsyncMock if asynchronous else MagicMock)(side_effect=browse))
    with pytest.raises(KeyError):
        await _call(client.read_value("T.new"))  # the catalog is fresh, so a check cannot help
    client.refresh_caches_if_program_changed.assert_not_called()
