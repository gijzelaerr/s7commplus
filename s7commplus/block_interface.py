"""Parse data-block, FB, OB and UDT interfaces from S7CommPlus EXPLORE responses.

A block object answers an EXPLORE with a ``<BlockInterface>`` document,
compressed against a Siemens preset dictionary (``DebugInfo_IntfDesc`` /
Adler-32 ``0x66052b13``). Its ``<Member>`` entries carry their data type as a
*reference* (``RID="0x0200_00XX"``) into the Siemens SoftDataType table, not as
an inline string. Parsed into :class:`Member`, or into a :class:`BlockInterface`
that also names the blocks the interface is built from.

``LineComm`` comments key each member by a colon-joined path of interface ids;
:func:`resolve_id_path` turns such a path into member names.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .blob_decompressor import find_preset_stream, decompress_blob

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

# A quoted UDT or FB name a member type is, bare ("Motor") or as the element type of an array (Array[0..1] of "Motor").
# Quoted constants inside the bounds (Array[0.."N"] of Bool) are not types, so only the whole string or the part after " of " counts.
# An unquoted name is not matched: UDTs also appear so (PC_Flags_V2), but Int looks the same.
_TYPE_BLOCK = re.compile(r'(?:Array\[.*\] of )?"([^"]+)"')
# The bounds of an array type, up to its element type.
_ARRAY_PREFIX = re.compile(r"Array\[.*\] of ")

# One segment of a LineComm <Comment Path="...">: a member ID plus, for an array
# element, the index list that selects it ("51[0,0]").
_ID_PATH_SEGMENT = re.compile(r"(\d{1,10})(\[-?\d{1,10}(?:,-?\d{1,10})*])?")


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

    @property
    def element_type(self) -> str:
        """The type of this member, or of each element of this array member, without the array bounds or quotes.

        It names a UDT or FB, a library type such as ``IEC_TIMER`` and an elementary type such as ``Int`` alike.
        """
        return _ARRAY_PREFIX.sub("", self.data_type, count=1).strip('"')


@dataclass
class BlockInterface:
    """A parsed ``<BlockInterface>`` document: its members and the blocks it is built from.

    Attributes:
        members: The block's top-level members, as :func:`parse_block_interface` returns them.
        source: The FB an instance DB copies its interface from, or None for any
            other interface. A DB declared of a UDT has no source.
        references: Names of the other blocks the interface mentions: the ``Block``
            of every ``<Part>``, every ``<ExternalType>`` and every UDT or FB a
            member ``Type`` quotes, array element types included. A member ``Type``
            that names a UDT without quotes is not listed unless a ``<Part>`` or
            ``<ExternalType>`` also names it. The block's own name is left out.
    """

    members: list[Member]
    source: str | None
    references: frozenset[str]

    @classmethod
    def from_xml(cls, xml_text: str, max_members: int = 250_000, max_depth: int = 64) -> BlockInterface:
        """Parse a decompressed ``<BlockInterface>`` document into members, source and references.

        Members and limits are as for :func:`parse_block_interface`. The references
        are read from the XML, not from the member tree: the tree misses the UDT a
        "DB of type" is declared with and UDTs named only in an ``<ExternalType>``.

        Raises:
            ValueError: The text is not well-formed XML, or the interface exceeds
                the limits of :func:`parse_block_interface`.
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise ValueError(f"Block interface XML is not well-formed: {exc}") from exc
        references = {part.get("Block", "") for part in root.iter("Part")}
        references |= {external.get("Name", "") for external in root.iter("ExternalType")}
        # A member type names a block only when quoted: an unquoted one cannot be told from an elementary
        # type, and a block named so comes in through its Part or ExternalType. This also keeps a bound
        # constant (Array[0.."N"] of Bool) out of the references.
        references |= {
            matched.group(1) for member in root.iter("Member") if (matched := _TYPE_BLOCK.fullmatch(member.get("Type", "")))
        }
        primary = root.find("Part")  # first top-level Part = the block's own source
        if primary is not None:
            references.discard(primary.get("Block", ""))
        references.discard("")

        source = None
        if primary is not None and primary.get("Kind") == "Values":
            # An instance DB or a DB of a UDT embeds the FB or UDT it is declared with below its Values part;
            # only a BlockSource there makes it an instance. ``VersionElement`` also names the FB, but
            # truncated or with its library path; ``Block`` is the reliable one.
            primary = primary.find("SubParts/Part")
            if primary is not None and primary.get("Kind") == "BlockSource":
                source = primary.get("Block") or None
        if source:
            references.discard(source)
        members = [] if primary is None else _parse_source_part(primary, "", set(), _ExpansionLimits(max_members, max_depth))
        return cls(members=members, source=source, references=frozenset(references))

    @classmethod
    def from_explore(cls, explore_payload: bytes, max_members: int = 250_000, max_depth: int = 64) -> BlockInterface:
        """Decompress a block EXPLORE payload and parse it like :meth:`from_xml`.

        The response bundles several preset-dict streams (IdentES, interface,
        comments, ...); this picks the interface dictionary, not the first stream.
        Without one the result has no members, no source and no references.

        Raises:
            ValueError: The stream does not decompress or is not well-formed XML, or
                the interface exceeds the limits of :func:`parse_block_interface`.
        """
        pos = find_preset_stream(explore_payload, _INTFDESC_KINDS)
        if pos is None:
            return cls(members=[], source=None, references=frozenset())
        try:
            return cls.from_xml(decompress_blob(explore_payload, offset=pos), max_members, max_depth)
        # a ParseError arrives as a ValueError from from_xml
        except zlib.error as exc:
            raise ValueError(f"Block interface EXPLORE payload is corrupt: {exc}") from exc


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


def parse_block_interface(xml_text: str, max_members: int = 250_000, max_depth: int = 64) -> list[Member]:
    """Parse a decompressed ``<BlockInterface>`` document into :class:`Member`s.

    Use :meth:`BlockInterface.from_xml` to also get the source and references.

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
    return BlockInterface.from_xml(xml_text, max_members, max_depth).members


def block_interface_from_explore(explore_payload: bytes, max_members: int = 250_000, max_depth: int = 64) -> list[Member]:
    """Decompress a block EXPLORE payload and parse its interface members.

    Picks the interface stream like :meth:`BlockInterface.from_explore`, which also
    returns the source and references. Returns an empty list if no interface stream
    is present.

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
    return BlockInterface.from_explore(explore_payload, max_members, max_depth).members


def resolve_id_path(
    members: Sequence[Member], id_path: str, *, types: Mapping[str, Sequence[Member]] | None = None
) -> str | None:
    """Turn a ``LineComm`` id path into the dotted member name path it refers to.

    Each segment is a :attr:`Member.id` among the fields of the previous
    segment's member, so the path is walked down the member tree. A DB writes
    the comment on a UDT member as ``<Comment Path="60:51">``, where 51 is the
    UDT's own id; the walk finds it in the fields the interface embedded for
    member 60. An array element keeps its index list: ``51[0,1]`` resolves to
    ``name[0,1]``.

    A member whose type the interface did not embed has no fields. The walk
    continues in the members `types` holds for its :attr:`Member.element_type`,
    and a path below a type that is in neither is not resolved.

    Example::

        interface = BlockInterface.from_xml(xml_text)
        resolve_id_path(interface.members, "60:51[2]")  # "motor.speeds[2]"

    Args:
        members: Member tree of the block the path starts in.
        id_path: Colon-joined path as written in a ``<Comment Path="...">``.
        types: Members of the types the interface did not embed, by name: the
            interface of a UDT or FB explored on its own, or a library type such
            as ``IEC_TIMER``. :attr:`BlockInterface.references` names the UDTs and FBs.

    Returns:
        The dotted name path, or None when a segment is malformed or names no member.
    """
    names: list[str] = []
    for segment in id_path.split(":"):
        matched = _ID_PATH_SEGMENT.fullmatch(segment)
        if matched is None:
            return None
        member_id = int(matched.group(1))
        entry = next((member for member in members if member.id == member_id), None)
        if entry is None:
            return None
        names.append(entry.name + (matched.group(2) or ""))
        # an embedded type carries its own ids; only a missing one needs the caller's types.
        # An inline Struct is always embedded, so an empty one must not be looked up there.
        if entry.fields or entry.element_type == "Struct":
            members = entry.fields
        else:
            members = (types or {}).get(entry.element_type, ())
    return ".".join(names)
