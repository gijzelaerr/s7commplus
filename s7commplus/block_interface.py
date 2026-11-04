"""Parse data-block and FB interfaces from S7CommPlus EXPLORE responses.

S7-1200/1500 PLCs answer a block EXPLORE request with zlib blobs compressed
against Siemens preset dictionaries. The interface blob decompresses to a
``<BlockInterface>`` with ``<Member>`` entries whose data type is a
*reference* (``RID="0x0200_00XX"``) into the Siemens SoftDataType table, not an
inline string (dict ``DebugInfo_IntfDesc`` / Adler-32 ``0x66052b13``). Parsed
into :class:`Member`.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field

from .blob_decompressor import decompress_blob, iter_preset_headers

# Interface-description preset-dict kinds, most preferred first. ``DebugInfo IntfDesc``
# carries the optimized (symbolic-access) block interface; ``IntfDesc`` the standard one.
_INTFDESC_KINDS = ("DebugInfo IntfDesc", "IntfDesc")

# Siemens SoftDataType ids, from thomas-v2/S7CommPlusDriver Core/Softdatatype.cs
# (LGPL-3.0). A <Member> type is a RID of the form 0x0200_00XX where XX is the
# SoftDataType id below.
SOFTDATATYPE = {
    0: "Void",
    1: "Bool",
    2: "Byte",
    3: "Char",
    4: "Word",
    5: "Int",
    6: "DWord",
    7: "DInt",
    8: "Real",
    9: "Date",
    10: "TimeOfDay",
    11: "Time",
    12: "S5Time",
    13: "S5Count",
    14: "DateAndTime",
    15: "InternetTime",
    16: "Array",
    17: "Struct",
    18: "EndStruct",
    19: "String",
    20: "Pointer",
    21: "MultiFB",
    22: "Any",
    23: "BlockFB",
    24: "BlockFC",
    25: "BlockDB",
    26: "BlockSDB",
    28: "Counter",
    29: "Timer",
    30: "IEC_Counter",
    31: "IEC_Timer",
    37: "BlockUDT",
    40: "BBool",
    48: "LReal",
    49: "ULInt",
    50: "LInt",
    51: "LWord",
    52: "USInt",
    53: "UInt",
    54: "UDInt",
    55: "SInt",
    61: "WChar",
    62: "WString",
    63: "Variant",
    64: "LTime",
    65: "LTimeOfDay",
    66: "LDT",
    67: "DTL",
}


@dataclass
class Member:
    """A single variable inside a data block or FB/OB interface."""

    name: str
    data_type: str  # readable type: SoftDataType name or the inline complex type
    lid: int
    offset: int  # StdO: standard (non-optimized) byte offset
    rid: int  # raw type RID
    section: str = ""  # Input/Output/InOut/Static/Temp/Constant (FB/OB); "" for a DB
    fields: list[Member] = field(default_factory=list)  # sub-members for a UDT/Struct type
    id: int = 0  # interface ID, unique among its siblings


@dataclass
class _ExpansionLimits:
    """Caps how far one interface may expand: total members and nesting depth."""

    max_members: int
    max_depth: int
    used: int = 0

    def take_member(self) -> None:
        if self.used == self.max_members:
            raise ValueError(f"Block interface expands to more than {self.max_members} members")
        self.used += 1

    def check_depth(self, path: set[int]) -> None:
        # `path` holds the parts being expanded, so its size is the nesting depth
        if len(path) >= self.max_depth:
            raise ValueError(f"Block interface nests deeper than {self.max_depth} levels")


def _member_type(member: ET.Element, target: ET.Element | None) -> str:
    """Resolve a ``<Member>``'s data type to a readable name.

    Complex members (arrays, UDTs, strings) already carry a ready-made
    ``Type`` attribute (e.g. ``Array[0..5] of IEC_TIMER``). Scalar elementary
    members carry only a RID of the form ``0x0200_00XX`` whose low byte is a
    Siemens SoftDataType id. (Arrays use ``0x0201_00XX``, hence the explicit
    ``Type``; the raw RID stays available on :attr:`Member.rid`.)

    An inline Struct carries neither a ``Type`` nor an elementary RID; its
    ``SubPartIndex`` points at a ``Kind="Structure"`` part instead.
    """
    explicit = member.get("Type")
    if explicit:
        return explicit
    if target is not None and target.get("Kind") == "Structure":
        return "Struct"
    try:
        rid = int(member.get("RID", "0") or "0", 16)
    except ValueError:
        return ""
    if (rid & 0xFFFF0000) == 0x02000000:
        return SOFTDATATYPE.get(rid & 0xFFFF, f"SoftType#{rid & 0xFFFF}")
    return f"0x{rid:08X}"


def parse_block_interface(xml_text: str, max_members: int = 250_000, max_depth: int = 64) -> list[Member]:
    """Parse a decompressed ``<BlockInterface>`` document into :class:`Member`s.

    Works for DB, FB, OB and UDT interfaces. The block's own variables come from
    its primary ``<Part>`` — directly under ``<Payload><Root>`` for a flat
    DB/UDT, or from the ``<Part Kind="*Section">`` entries for an FB/OB. Members
    are returned in declaration order, each tagged with its section
    (Input/Output/... for FB/OB; empty for DB/UDT).

    When a member is of a UDT, an FB or an inline Struct, the interface embeds
    that type's definition under the primary part's ``<SubParts>``; the member's
    ``SubPartIndex`` selects it. Such members are expanded recursively into
    :attr:`Member.fields`. Library types (e.g. ``IEC_TIMER``) are referenced but
    not inlined, so they expand to no fields.

    An instance DB or a UDT-typed DB has no source part of its own: its first
    ``<Part>`` is ``Kind="Values"``, and its members come from the FB or UDT
    embedded in that part's ``<SubParts>``.

    Several members may point at the same part, so a small document can expand
    to exponentially many members. ``max_members`` caps the total, counted
    across every nesting level, and ``max_depth`` keeps a long chain of parts
    from exhausting Python's recursion limit.

    Args:
        xml_text: The decompressed ``<BlockInterface>`` XML.
        max_members: The most members, nested ones included, the interface may expand to.
        max_depth: The most levels of nested parts the interface may expand to.

    Returns:
        The block's top-level members, with nested members in :attr:`Member.fields`.

    Raises:
        ValueError: The interface expands to more than ``max_members`` members
            or nests deeper than ``max_depth`` levels.
    """
    root = ET.fromstring(xml_text)
    primary = root.find("Part")  # first top-level Part = the block's own source
    if primary is not None and primary.get("Kind") == "Values":
        primary = primary.find("SubParts/Part")
    if primary is None:
        return []
    return _parse_source_part(primary, "", set(), _ExpansionLimits(max_members, max_depth))


def _parse_source_part(part: ET.Element, section: str, seen: set[int], limits: _ExpansionLimits) -> list[Member]:
    """Parse one source ``<Part>`` (DBSource/BlockSource/DataTypeSource).

    ``seen`` carries the identities of the ``<Part>`` elements already being
    expanded on the current path, so a malformed ``SubPartIndex`` cycle stops
    instead of recursing forever.
    """
    sub_el = part.find("SubParts")
    subparts = list(sub_el) if sub_el is not None else []  # index-addressable

    # Flat DB/UDT: variables are direct <Member> children of <Payload><Root>.
    # A UDT's fields inherit the section of the member typed with it, like a Struct's fields do.
    members = _build_members(part.findall("./Payload/Root"), section, subparts, seen, limits)
    # FB/OB: variables live in the <Part Kind="*Section"> entries of <SubParts>.
    for sp in subparts:
        kind = sp.get("Kind", "")
        if not kind.endswith("Section"):
            continue
        members += _build_members(sp.findall("./Payload/Member"), kind[: -len("Section")], subparts, seen, limits)
    return members


def _build_members(
    containers: list[ET.Element], section: str, subparts: list[ET.Element], seen: set[int], limits: _ExpansionLimits
) -> list[Member]:
    """Build the RID-carrying ``<Member>`` children of `containers`; section headers have no RID."""
    return [
        _build_member(m, section, subparts, seen, limits)
        for c in containers
        for m in c.findall("Member")
        if m.get("RID") is not None
    ]


def _build_member(m: ET.Element, section: str, subparts: list[ET.Element], seen: set[int], limits: _ExpansionLimits) -> Member:
    """Build a :class:`Member`, expanding a structured type via ``SubPartIndex``."""
    limits.take_member()
    target = _subpart(m, subparts, seen)
    return Member(
        name=m.get("Name", ""),
        data_type=_member_type(m, target),
        lid=int(m.get("LID", "0")),
        offset=int(m.get("StdO", "0")),
        rid=int(m.get("RID", "0") or "0", 16),
        section=section,
        fields=_member_fields(target, section, subparts, seen, limits),
        id=int(m.get("ID", "0")),
    )


def _subpart(m: ET.Element, subparts: list[ET.Element], seen: set[int]) -> ET.Element | None:
    """Return the part a member's ``SubPartIndex`` selects, or None if absent, out of range or already on the path."""
    idx = int(m.get("SubPartIndex", "-1"))
    if not 0 <= idx < len(subparts) or id(subparts[idx]) in seen:
        return None
    return subparts[idx]


def _member_fields(
    target: ET.Element | None, section: str, subparts: list[ET.Element], seen: set[int], limits: _ExpansionLimits
) -> list[Member]:
    """Expand a member's ``SubPartIndex`` target into its sub-members."""
    if target is None:
        return []
    limits.check_depth(seen)
    kind = target.get("Kind", "")
    # An inlined type definition (a *Source part) has its own SubParts; an inline
    # Struct's nested Structure parts sit in the same list as its own part.
    # A *Section index or a library reference expands to nothing.
    if kind.endswith("Source"):
        return _parse_source_part(target, section, seen | {id(target)}, limits)
    if kind == "Structure":
        return _build_members(target.findall("./Payload/Member"), section, subparts, seen | {id(target)}, limits)
    return []


def block_interface_from_explore(explore_payload: bytes, max_members: int = 250_000, max_depth: int = 64) -> list[Member]:
    """Decompress a block EXPLORE payload and parse its interface members.

    The EXPLORE response for a block RID bundles several preset-dict streams
    (IdentES, interface, comments, ...). This targets the interface dictionary
    specifically rather than taking the first stream. Returns an empty list if
    no interface stream is present.

    Args:
        explore_payload: The EXPLORE response payload for a block.
        max_members: The most members, nested ones included, the interface may
            expand to; see :func:`parse_block_interface`.
        max_depth: The most levels of nested parts the interface may expand to.

    Raises:
        ValueError: The stream does not decompress or is not well-formed XML,
            or the interface expands to more than ``max_members`` members or
            nests deeper than ``max_depth`` levels.
    """
    pos = _find_preset_stream(explore_payload, _INTFDESC_KINDS)
    if pos is None:
        return []
    try:
        return parse_block_interface(decompress_blob(explore_payload, offset=pos), max_members, max_depth)
    except (zlib.error, ET.ParseError) as exc:
        raise ValueError(f"Block interface EXPLORE payload is corrupt: {exc}") from exc


def _find_preset_stream(data: bytes, kinds: tuple[str, ...]) -> int | None:
    """Return the offset of the first preset-dict stream of the most preferred kind in `kinds`.

    A block EXPLORE response contains several preset-dict streams; callers need
    the one for a specific dictionary kind, not merely the first. Only headers
    are read, so the other streams are never decompressed.

    Matching by kind alone also accepts any future version of a dictionary, so
    adding a second version of one of these kinds feeds its streams to the same
    parser.
    """
    offsets: dict[str, int] = {}
    for offset, preset in iter_preset_headers(data):
        if preset.kind in kinds:
            offsets.setdefault(preset.kind, offset)
    for kind in kinds:
        if kind in offsets:
            return offsets[kind]
    return None
