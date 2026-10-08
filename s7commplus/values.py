"""Python values for PLC tags: per-type conversion and struct/array assembly.

A tag's raw bytes are what :meth:`Client.read_tags` returns and
:meth:`Client.write_tags` sends. This module turns them into Python values and
back, by the tag's PLC datatype, and rebuilds structs and arrays from the
browsed leaves (the tag catalog lists one tag per scalar leaf: every struct,
UDT and DTL member and every array element).

The layouts were read from, and the writes accepted by, PLCSIM Advanced (CPU
1511, FW V2.9) with one member per datatype; they follow the TIA Portal
memory formats. They are not yet checked on real hardware.

The value ranges are those of the TIA Portal data type documentation (STEP 7
online help, "Date and time" and "Character strings" data types), not verified
on hardware: DATE 1990-01-01 to 2168-12-31, DATE_AND_TIME 1990 to 2089, LDT and
DTL 1970-01-01 to 2262-04-11 23:47:16.854775807, STRING up to 254 and WSTRING
up to 16382 characters.

No PLC date or time type stores a time zone, so these functions take and give
naive :class:`datetime.datetime` and :class:`datetime.time` values; an aware
one raises :class:`ValueError` rather than being silently shifted or stripped.
Convert it first, for example with
``value.astimezone(datetime.timezone.utc).replace(tzinfo=None)``.
"""

from __future__ import annotations

import datetime
import re
import struct
from collections.abc import Mapping, Sequence
from typing import Any

from .typeinfo import Softdatatype

__all__ = ["assemble", "decode", "encode", "split"]

_EPOCH_1990 = datetime.date(1990, 1, 1)
_EPOCH_1970 = datetime.datetime(1970, 1, 1)
_MS_PER_DAY = 86_400_000
_NS_PER_DAY = 86_400_000_000_000

# Ranges from the TIA Portal data type documentation; not verified on hardware.
_DATE_MAX_DAYS = (datetime.date(2168, 12, 31) - _EPOCH_1990).days  # D#2168-12-31
_LDT_MAX_NS = 2**63 - 1  # LDT#2262-04-11-23:47:16.854775807: a signed 64-bit nanosecond count
_LDT_RANGE = "1970-01-01 to 2262-04-11 23:47:16.854775807"
_STRING_MAX = 254
_WSTRING_MAX = 16382

_FORMATS: dict[Softdatatype, str] = {
    Softdatatype.BYTE: ">B",
    Softdatatype.WORD: ">H",
    Softdatatype.DWORD: ">I",
    Softdatatype.LWORD: ">Q",
    Softdatatype.SINT: ">b",
    Softdatatype.INT: ">h",
    Softdatatype.DINT: ">i",
    Softdatatype.LINT: ">q",
    Softdatatype.USINT: ">B",
    Softdatatype.UINT: ">H",
    Softdatatype.UDINT: ">I",
    Softdatatype.ULINT: ">Q",
    Softdatatype.REAL: ">f",
    Softdatatype.LREAL: ">d",
}

_S5_BASES_MS = (10, 100, 1000, 10000)


class _Undecodable(Exception):
    """The raw bytes do not hold a valid value of the type; keep them as bytes."""


def _bcd(byte: int) -> int:
    high, low = byte >> 4, byte & 0x0F
    if high > 9 or low > 9:
        raise _Undecodable
    return high * 10 + low


def _to_bcd(value: int) -> int:
    return (value // 10) << 4 | value % 10


def _ns_to_timedelta(ns: int) -> datetime.timedelta:
    # Truncate toward zero: a timedelta holds no sub-microsecond part.
    microseconds = abs(ns) // 1000
    return datetime.timedelta(microseconds=microseconds if ns >= 0 else -microseconds)


def _time_of_day(microseconds: int) -> datetime.time:
    seconds, micro = divmod(microseconds, 1_000_000)
    minutes, second = divmod(seconds, 60)
    hour, minute = divmod(minutes, 60)
    return datetime.time(hour, minute, second, micro)


def _microseconds_since_midnight(value: datetime.time) -> int:
    return ((value.hour * 60 + value.minute) * 60 + value.second) * 1_000_000 + value.microsecond


def _decode(softdatatype: Softdatatype, raw: bytes) -> Any:
    if softdatatype in (Softdatatype.BOOL, Softdatatype.BBOOL):
        if len(raw) != 1:
            raise _Undecodable
        return raw[0] != 0
    fmt = _FORMATS.get(softdatatype)
    if fmt is not None:
        if len(raw) != struct.calcsize(fmt):
            raise _Undecodable
        return struct.unpack(fmt, raw)[0]
    if softdatatype is Softdatatype.CHAR:
        if len(raw) != 1:
            raise _Undecodable
        return raw.decode("latin-1")
    if softdatatype is Softdatatype.WCHAR:
        if len(raw) != 2:
            raise _Undecodable
        try:
            return raw.decode("utf-16-be")
        except UnicodeDecodeError as exc:
            raise _Undecodable from exc
    if softdatatype is Softdatatype.STRING:
        # [max length][current length][characters, padded to max length]
        if len(raw) < 2 or raw[0] > _STRING_MAX or raw[1] > raw[0] or 2 + raw[1] > len(raw):
            raise _Undecodable
        return raw[2 : 2 + raw[1]].decode("latin-1")
    if softdatatype is Softdatatype.WSTRING:
        if len(raw) < 4:
            raise _Undecodable
        maximum, length = struct.unpack_from(">HH", raw)
        if maximum > _WSTRING_MAX or length > maximum or 4 + 2 * length > len(raw):
            raise _Undecodable
        try:
            return raw[4 : 4 + 2 * length].decode("utf-16-be")
        except UnicodeDecodeError as exc:
            raise _Undecodable from exc
    if softdatatype is Softdatatype.DATE:
        if len(raw) != 2:
            raise _Undecodable
        days = struct.unpack(">H", raw)[0]
        if days > _DATE_MAX_DAYS:
            raise _Undecodable
        return _EPOCH_1990 + datetime.timedelta(days=days)
    if softdatatype is Softdatatype.TIME:
        if len(raw) != 4:
            raise _Undecodable
        return datetime.timedelta(milliseconds=struct.unpack(">i", raw)[0])
    if softdatatype is Softdatatype.LTIME:
        if len(raw) != 8:
            raise _Undecodable
        return _ns_to_timedelta(struct.unpack(">q", raw)[0])
    if softdatatype is Softdatatype.TIMEOFDAY:
        if len(raw) != 4:
            raise _Undecodable
        ms = struct.unpack(">I", raw)[0]
        if ms >= _MS_PER_DAY:
            raise _Undecodable
        return _time_of_day(ms * 1000)
    if softdatatype is Softdatatype.LTOD:
        if len(raw) != 8:
            raise _Undecodable
        ns = struct.unpack(">Q", raw)[0]
        if ns >= _NS_PER_DAY:
            raise _Undecodable
        return _time_of_day(ns // 1000)
    if softdatatype is Softdatatype.LDT:
        if len(raw) != 8:
            raise _Undecodable
        ns = struct.unpack(">q", raw)[0]
        if ns < 0:
            raise _Undecodable
        return _EPOCH_1970 + datetime.timedelta(microseconds=ns // 1000)
    if softdatatype is Softdatatype.DATEANDTIME:
        # BCD: year, month, day, hour, minute, second, two and a half bytes of
        # milliseconds, then the weekday nibble (1 = Sunday).
        if len(raw) != 8:
            raise _Undecodable
        year, month, day, hour, minute, second = (_bcd(byte) for byte in raw[:6])
        if raw[7] >> 4 > 9:
            raise _Undecodable
        milliseconds = _bcd(raw[6]) * 10 + (raw[7] >> 4)
        try:
            return datetime.datetime(year + (1900 if year >= 90 else 2000), month, day, hour, minute, second, milliseconds * 1000)
        except ValueError as exc:
            raise _Undecodable from exc
    if softdatatype is Softdatatype.S5TIME:
        if len(raw) != 2:
            raise _Undecodable
        word = struct.unpack(">H", raw)[0]
        base = _S5_BASES_MS[(word >> 12) & 0x3]
        value = _bcd((word >> 8) & 0x0F) * 100 + _bcd(word & 0xFF)
        return datetime.timedelta(milliseconds=value * base)
    raise _Undecodable


def decode(softdatatype: Softdatatype, raw: bytes) -> Any:
    """Return the Python value of ``raw``, or ``raw`` itself when it cannot be decoded.

    Integers and bit strings become ``int``, REAL/LREAL ``float``, BOOL ``bool``,
    CHAR/WCHAR/STRING/WSTRING ``str`` (single-byte types as Latin-1), DATE a
    :class:`datetime.date`, TIME/LTIME/S5TIME a :class:`datetime.timedelta`,
    TIME_OF_DAY/LTOD a :class:`datetime.time`, and DATE_AND_TIME/LDT a naive
    :class:`datetime.datetime`. Nanosecond types are truncated to microseconds;
    write an ``int`` of nanoseconds to keep the full precision. Bytes of the
    wrong length or outside the type's range (see the module documentation) are
    returned unchanged.
    """
    try:
        return _decode(softdatatype, raw)
    except _Undecodable:
        return raw


def _whole(value: datetime.timedelta, unit_us: int, name: str) -> int:
    microseconds = (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds
    if microseconds % unit_us:
        raise ValueError(f"{name} holds whole {'milliseconds' if unit_us == 1000 else f'{unit_us} µs units'}, got {value}")
    return microseconds // unit_us


def _pack(fmt: str, value: Any, name: str) -> bytes:
    try:
        return struct.pack(fmt, value)
    except (struct.error, OverflowError) as exc:
        raise ValueError(f"{value!r} does not fit a {name}") from exc


def _require_naive(value: datetime.datetime | datetime.time, name: str) -> None:
    if value.tzinfo is not None:
        raise ValueError(f"{name} stores no time zone; convert {value} to a naive value first")


def encode(softdatatype: Softdatatype, value: Any, *, string_length: int = 0) -> bytes:
    """Return the raw bytes of ``value`` for a tag of ``softdatatype``.

    Accepts the types :func:`decode` returns. BOOL also takes ``0`` or ``1``,
    and REAL/LREAL an ``int`` and the infinities and NaN, which the PLC stores
    like any other IEEE 754 value. Time types also take an ``int`` in their own
    unit (milliseconds for TIME, TIME_OF_DAY and S5TIME, nanoseconds for LTIME,
    LTOD and LDT). Date and time values must be naive. ``string_length`` is the
    declared length of a STRING (up to 254) or WSTRING (up to 16382); ``0``
    means unknown and is taken as 254.

    Raises:
        TypeError: ``value`` has the wrong Python type.
        ValueError: ``value`` is out of range for the PLC type, carries a time
            zone, or ``string_length`` is out of range.
    """
    name = softdatatype.name
    if softdatatype in (Softdatatype.BOOL, Softdatatype.BBOOL):
        if not isinstance(value, int):
            raise TypeError(f"{name} takes a bool, got {type(value).__name__}")
        if value not in (0, 1):
            raise ValueError(f"{name} takes a bool, 0 or 1, got {value!r}")
        return b"\x01" if value else b"\x00"
    fmt = _FORMATS.get(softdatatype)
    if fmt is not None:
        if softdatatype in (Softdatatype.REAL, Softdatatype.LREAL):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise TypeError(f"{name} takes a float, got {type(value).__name__}")
        elif not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} takes an int, got {type(value).__name__}")
        return _pack(fmt, value, name)
    if softdatatype in (Softdatatype.CHAR, Softdatatype.WCHAR):
        if not isinstance(value, str) or len(value) != 1:
            raise TypeError(f"{name} takes a one-character str, got {value!r}")
        try:
            raw = value.encode("latin-1" if softdatatype is Softdatatype.CHAR else "utf-16-be")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{value!r} cannot be stored in a {name}") from exc
        if len(raw) != (1 if softdatatype is Softdatatype.CHAR else 2):
            raise ValueError(f"{value!r} cannot be stored in a {name}")
        return raw
    if softdatatype in (Softdatatype.STRING, Softdatatype.WSTRING):
        if not isinstance(value, str):
            raise TypeError(f"{name} takes a str, got {type(value).__name__}")
        wide = softdatatype is Softdatatype.WSTRING
        limit = _WSTRING_MAX if wide else _STRING_MAX
        if not 0 <= string_length <= limit:
            raise ValueError(f"A {name} is declared with 1 to {limit} characters, got {string_length}")
        maximum = string_length or 254
        try:
            chars = value.encode("utf-16-be" if wide else "latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{value!r} cannot be stored in a {name}") from exc
        length = len(chars) // 2 if wide else len(chars)
        if length > maximum:
            raise ValueError(f"{name}[{maximum}] holds at most {maximum} characters, got {length}")
        # Padded to the declared length: an element of an Array of String is
        # rejected otherwise (PLCSIM Advanced, CPU 1511, FW V2.9).
        padding = bytes((maximum - length) * (2 if wide else 1))
        return struct.pack(">HH" if wide else ">BB", maximum, length) + chars + padding
    if softdatatype is Softdatatype.DATE:
        if isinstance(value, datetime.datetime) or not isinstance(value, datetime.date):
            raise TypeError(f"DATE takes a datetime.date, got {type(value).__name__}")
        days = (value - _EPOCH_1990).days
        if not 0 <= days <= _DATE_MAX_DAYS:
            raise ValueError(f"DATE holds 1990-01-01 to 2168-12-31, got {value}")
        return struct.pack(">H", days)
    if softdatatype in (Softdatatype.TIME, Softdatatype.LTIME, Softdatatype.S5TIME):
        if isinstance(value, datetime.timedelta):
            amount = _whole(value, 1 if softdatatype is Softdatatype.LTIME else 1000, name)
            if softdatatype is Softdatatype.LTIME:
                amount *= 1000
        elif isinstance(value, int) and not isinstance(value, bool):
            amount = value
        else:
            raise TypeError(f"{name} takes a datetime.timedelta or an int, got {type(value).__name__}")
        if softdatatype is Softdatatype.TIME:
            return _pack(">i", amount, name)
        if softdatatype is Softdatatype.LTIME:
            return _pack(">q", amount, name)
        for index, base in enumerate(_S5_BASES_MS):
            if amount >= 0 and amount % base == 0 and amount // base <= 999:
                count = amount // base
                return struct.pack(">H", index << 12 | (count // 100) << 8 | _to_bcd(count % 100))
        raise ValueError(f"S5TIME cannot hold {amount} ms (0 to 9990 s, in steps of its time base)")
    if softdatatype in (Softdatatype.TIMEOFDAY, Softdatatype.LTOD):
        nanos = softdatatype is Softdatatype.LTOD
        if isinstance(value, datetime.time):
            _require_naive(value, name)
            microseconds = _microseconds_since_midnight(value)
            if not nanos and microseconds % 1000:
                raise ValueError(f"TIME_OF_DAY holds whole milliseconds, got {value}")
            amount = microseconds * 1000 if nanos else microseconds // 1000
        elif isinstance(value, int) and not isinstance(value, bool):
            amount = value
        else:
            raise TypeError(f"{name} takes a datetime.time or an int, got {type(value).__name__}")
        if not 0 <= amount < (_NS_PER_DAY if nanos else _MS_PER_DAY):
            raise ValueError(f"{name} must be within one day, got {amount}")
        return struct.pack(">Q" if nanos else ">I", amount)
    if softdatatype is Softdatatype.LDT:
        if isinstance(value, datetime.datetime):
            _require_naive(value, name)
            delta = value - _EPOCH_1970
            amount = ((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
        elif isinstance(value, int) and not isinstance(value, bool):
            amount = value
        else:
            raise TypeError(f"LDT takes a datetime.datetime or an int, got {type(value).__name__}")
        if not 0 <= amount <= _LDT_MAX_NS:
            raise ValueError(f"LDT holds {_LDT_RANGE}, got {value}")
        return struct.pack(">q", amount)
    if softdatatype is Softdatatype.DATEANDTIME:
        if not isinstance(value, datetime.datetime):
            raise TypeError(f"DATE_AND_TIME takes a datetime.datetime, got {type(value).__name__}")
        _require_naive(value, "DATE_AND_TIME")
        if not 1990 <= value.year <= 2089:
            raise ValueError(f"DATE_AND_TIME holds 1990 to 2089, got {value.year}")
        if value.microsecond % 1000:
            raise ValueError(f"DATE_AND_TIME holds whole milliseconds, got {value}")
        milliseconds = value.microsecond // 1000
        weekday = value.isoweekday() % 7 + 1  # 1 = Sunday
        fields = (value.year % 100, value.month, value.day, value.hour, value.minute, value.second, milliseconds // 10)
        return bytes(_to_bcd(field) for field in fields) + bytes([(milliseconds % 10) << 4 | weekday])
    raise TypeError(f"Writing {name} values is not supported")


# --- Structs and arrays from catalog leaves ----------------------------------------------

_TOKEN = re.compile(r"\.([^.\[\]]+)|\[(-?\d+(?:,-?\d+)*)\]")

# A member path: member names and array indices (one int per dimension).
_Path = tuple[str | tuple[int, ...], ...]

# The members of a DTL, which the catalog lists as leaves of the DTL tag.
_DTL_MEMBERS = ("YEAR", "MONTH", "DAY", "WEEKDAY", "HOUR", "MINUTE", "SECOND", "NANOSECOND")
# DTL#2262-04-11-23:47:16.854775807, LDT's limit (TIA Portal documentation; not verified on hardware)
_DTL_MAX = _EPOCH_1970 + datetime.timedelta(microseconds=_LDT_MAX_NS // 1000)


def _member_path(prefix: str, name: str) -> _Path:
    """Split the part of ``name`` after ``prefix`` into member names and array indices.

    ``_member_path("DB.s", "DB.s.arr[1].x")`` is ``("arr", (1,), "x")``. Names that
    themselves contain ``.`` or ``[`` are split too, so such members nest one level
    deeper than declared.
    """
    rest = name[len(prefix) :]
    path: list[str | tuple[int, ...]] = []
    position = 0
    while position < len(rest):
        match = _TOKEN.match(rest, position)
        if match is None:
            raise ValueError(f"Cannot split {name!r} below {prefix!r}")
        member, indices = match.groups()
        path.append(member if member is not None else tuple(int(index) for index in indices.split(",")))
        position = match.end()
    return tuple(path)


def _is_member(prefix: str, name: str) -> bool:
    """Whether catalog name ``name`` lies inside the struct or array ``prefix``."""
    return len(name) > len(prefix) and name.startswith(prefix) and name[len(prefix)] in ".["


def _dtl(members: Mapping[str, Any]) -> Any:
    try:
        return datetime.datetime(
            members["YEAR"],
            members["MONTH"],
            members["DAY"],
            members["HOUR"],
            members["MINUTE"],
            members["SECOND"],
            members["NANOSECOND"] // 1000,
        )
    except (TypeError, ValueError):
        return dict(members)


def _finish(node: Any) -> Any:
    if not isinstance(node, dict):
        return node
    if node and all(isinstance(key, tuple) for key in node):
        return _nest_indices({key: _finish(value) for key, value in node.items()})
    members = {key: _finish(value) for key, value in node.items()}
    if set(members) == set(_DTL_MEMBERS):
        return _dtl(members)
    return members


def _nest_indices(elements: dict[Any, Any]) -> list[Any]:
    """Turn ``{(i, j, ...): value}`` into nested lists ordered by index."""
    if all(len(index) == 1 for index in elements):
        return [elements[index] for index in sorted(elements)]
    groups: dict[int, dict[Any, Any]] = {}
    for index, value in elements.items():
        groups.setdefault(index[0], {})[index[1:]] = value
    return [_nest_indices(groups[first]) for first in sorted(groups)]


def assemble(prefix: str, leaves: Sequence[tuple[str, Any]]) -> Any:
    """Build the struct (``dict``) or array (``list``) at ``prefix`` from its decoded leaves.

    Arrays become lists in index order (index 0 of the list is the declared lower
    bound); a multi-dimensional array becomes nested lists. A struct whose members
    are exactly a DTL's becomes a naive :class:`datetime.datetime` (nanoseconds
    truncated); one with an invalid date stays a ``dict``.
    """
    root: dict[Any, Any] = {}
    for name, value in leaves:
        path = _member_path(prefix, name)
        if not path:
            raise ValueError(f"{name!r} is not inside {prefix!r}")
        node = root
        for step in path[:-1]:
            child = node.setdefault(step, {})
            if not isinstance(child, dict):
                raise ValueError(f"{name!r} nests below the leaf {step!r}")
            node = child
        if path[-1] in node:
            raise ValueError(f"{name!r} names a leaf twice or below another leaf")
        node[path[-1]] = value
    return _finish(root)


def _dtl_members(value: datetime.datetime) -> dict[str, int]:
    _require_naive(value, "DTL")
    if not _EPOCH_1970 <= value <= _DTL_MAX:
        raise ValueError(f"DTL holds {_LDT_RANGE}, got {value}")
    return {
        "YEAR": value.year,
        "MONTH": value.month,
        "DAY": value.day,
        "WEEKDAY": value.isoweekday() % 7 + 1,  # 1 = Sunday
        "HOUR": value.hour,
        "MINUTE": value.minute,
        "SECOND": value.second,
        "NANOSECOND": value.microsecond * 1000,
    }


def split(prefix: str, value: Any, leaf_names: Sequence[str]) -> dict[str, Any]:
    """Map ``value`` for the struct or array at ``prefix`` onto its leaf names.

    The inverse of :func:`assemble`. A ``dict`` may give only some members (the
    others are not written) but no unknown ones; a ``list`` or ``tuple`` must give
    every element of its array (nested lists for a multi-dimensional one), and a
    ``dict`` keyed by index may give some. A naive ``datetime`` is accepted for a
    DTL, and only for a DTL.

    Raises:
        TypeError: A struct is not given as a ``dict`` (or a DTL as a ``datetime``)
            or an array as a list.
        ValueError: A ``dict`` names an unknown member, a list has the wrong
            length, or a DTL's ``datetime`` is aware or out of range.
    """
    paths = {name: _member_path(prefix, name) for name in leaf_names}
    children: dict[_Path, list[Any]] = {}
    for path in paths.values():
        for depth, step in enumerate(path):
            known = children.setdefault(path[:depth], [])
            if step not in known:
                known.append(step)
    # The node at a path is the same for every leaf below it, so its keys are
    # checked once per path. (Keyed by id(), a DTL's temporary member dict could
    # share an id with a later one and skip that check.)
    checked: set[_Path] = set()
    result: dict[str, Any] = {}
    for name, path in paths.items():
        node: Any = value
        for depth, step in enumerate(path):
            here = path[:depth]
            if isinstance(node, datetime.datetime) and set(children[here]) == set(_DTL_MEMBERS):
                node = _dtl_members(node)
            if isinstance(node, Mapping):
                if here not in checked:
                    _check_keys(prefix, here, node, children[here])
                    checked.add(here)
                key = _key(node, step)
                if key is None:
                    break  # not given: this leaf is left unwritten
                node = node[key]
            elif isinstance(step, tuple):
                if not isinstance(node, (list, tuple)):
                    raise TypeError(f"{prefix}{_render(here)} is an array; give a list, got {type(node).__name__}")
                node = _element(node, step, children[here], f"{prefix}{_render(here)}")
            else:
                raise TypeError(f"{prefix}{_render(here)} is a struct; give a dict, got {type(node).__name__}")
        else:
            result[name] = node
    return result


def _key(node: Mapping[Any, Any], step: str | tuple[int, ...]) -> Any:
    if step in node:
        return step
    if isinstance(step, tuple) and len(step) == 1 and step[0] in node:
        return step[0]  # a one-dimensional index given as a plain int
    return None


def _check_keys(prefix: str, here: _Path, node: Mapping[Any, Any], allowed: list[Any]) -> None:
    for key in node:
        if key not in allowed and not (isinstance(key, int) and (key,) in allowed):
            raise ValueError(f"{prefix}{_render(here)} has no member or element {key!r}")


def _element(node: Sequence[Any], step: tuple[int, ...], indices: list[Any], where: str) -> Any:
    """Pick element ``step`` of an array given as a list (nested lists per dimension)."""
    for dimension, index in enumerate(step):
        values = sorted({full[dimension] for full in indices if full[:dimension] == step[:dimension]})
        if not isinstance(node, (list, tuple)):
            raise TypeError(f"{where} dimension {dimension + 1} must be a list, got {type(node).__name__}")
        if len(node) != len(values):
            raise ValueError(f"{where} dimension {dimension + 1} has {len(values)} elements, got {len(node)}")
        node = node[values.index(index)]
    return node


def _render(path: _Path) -> str:
    return "".join(f".{step}" if isinstance(step, str) else f"[{','.join(map(str, step))}]" for step in path)
