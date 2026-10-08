"""Typed tag values: per-type conversion of raw tag bytes.

Known-answer vectors are the raw bytes PLCSIM Advanced (CPU 1511, FW V2.9) returned for the
"Types DB" test block (one member per datatype) and the layouts it accepted on write.
"""

from __future__ import annotations

import datetime as dt
import math
from typing import Any

import pytest

from s7commplus import values
from s7commplus.catalog import SymbolCatalog, SymbolicTag
from s7commplus.typeinfo import Softdatatype as T

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
