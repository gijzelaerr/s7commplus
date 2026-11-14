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
# Most ids and their spelling were confirmed by browsing an S7-1500 (6ES7 512-1CK01,
# FW V2.9); the rest keep the thomas-v2 name.
# A trailing comment gives TIA Portal's spelling where the name here differs.
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
    10: "TimeOfDay",  # Time_Of_Day
    11: "Time",
    12: "S5Time",
    13: "S5Count",
    14: "DateAndTime",  # Date_And_Time
    15: "InternetTime",
    16: "Array",
    17: "Struct",
    18: "EndStruct",
    19: "String",
    20: "Pointer",
    21: "MultiFB",
    22: "Any",
    23: "BlockFB",  # Block_FB
    24: "BlockFC",  # Block_FC
    25: "BlockDB",
    26: "BlockSDB",
    28: "Counter",
    29: "Timer",
    30: "IEC_COUNTER",
    31: "IEC_TIMER",
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
    65: "LTimeOfDay",  # LTime_Of_Day
    66: "LDT",
    67: "DTL",
    68: "IEC_LTIMER",
    69: "IEC_SCOUNTER",
    70: "IEC_DCOUNTER",
    71: "IEC_LCOUNTER",
    72: "IEC_UCOUNTER",
    73: "IEC_USCOUNTER",
    74: "IEC_UDCOUNTER",
    75: "IEC_ULCOUNTER",
    96: "Remote",
    97: "ErrorStruct",
    98: "NREF",
    101: "CREF",
    128: "AOM_IDENT",
    129: "EVENT_ANY",
    130: "EVENT_ATT",
    134: "EVENT_HWINT",
    144: "HW_ANY",
    145: "HW_IOSYSTEM",
    146: "HW_DPMASTER",
    147: "HW_DEVICE",
    148: "HW_DPSLAVE",
    149: "HW_IO",
    150: "HW_MODULE",
    151: "HW_SUBMODULE",
    152: "HW_HSC",
    153: "HW_PWM",
    154: "HW_PTO",
    155: "HW_INTERFACE",
    156: "HW_IEPORT",
    160: "OB_ANY",
    161: "OB_DELAY",
    162: "OB_TOD",
    163: "OB_CYCLIC",
    164: "OB_ATT",
    168: "CONN_ANY",
    169: "CONN_PRG",
    170: "CONN_OUC",
    171: "CONN_R_ID",
    173: "PORT",
    174: "RTM",
    175: "PIP",
    192: "OB_PCYCLE",
    193: "OB_HWINT",
    195: "OB_DIAG",
    196: "OB_TIMEERROR",
    197: "OB_STARTUP",
    200: "OPC_UA_LocalizedTextEncodingMask",
    201: "OPC_UA_ByteStringActualLength",
    208: "DB_ANY",
    209: "DB_WWW",
    210: "DB_DYN",
}

# A quoted UDT or FB name a member type is, bare ("Motor") or as the element type of an array (Array[0..1] of "Motor").
# Quoted constants inside the bounds (Array[0.."N"] of Bool) are not types, so only the whole string or the part after " of " counts.
# An unquoted name is not matched: UDTs also appear so (PC_Flags_V2), but Int looks the same.
_TYPE_BLOCK = re.compile(r'(?:Array\[.*\] of )?"([^"]+)"')
# The bounds of an array type, up to its element type.
_ARRAY_PREFIX = re.compile(r"Array\[[^\]]*\] of ")

# One segment of a LineComm <Comment Path="...">: a member ID plus, for an array
# element, the index list that selects it ("51[0,0]").
_ID_PATH_SEGMENT = re.compile(r"(\d{1,10})(\[-?\d{1,10}(?:,-?\d{1,10})*])?")


# ParseError first: on Python 3.10 SyntaxError's __str__ shows msg, which only SyntaxError's __init__ sets
class BlockInterfaceError(ET.ParseError, ValueError):
    """Malformed block-interface XML.

    It is a `ValueError` and, for callers written against earlier versions, an
    `xml.etree.ElementTree.ParseError`.
    """


@dataclass
class Member:
    """A single variable inside a data block or FB/OB interface."""

    name: str
    data_type: str  # readable type: SoftDataType name or the inline complex type
    lid: int
    offset: int  # StdO: standard (non-optimized) byte offset
    rid: int  # raw type RID
    section: str = ""  # Input/Output/InOut/Static/Temp/Constant (FB/OB), also Return (FC); "" for a DB
    fields: list[Member] = field(default_factory=list)  # sub-members for a UDT/Struct type
    id: int = 0  # interface ID, unique among its siblings; 0 when the XML has none, which no path matches
    # the type a SubPartIndex references without the interface embedding it, as BlockInterface.references
    # names it; it can differ from element_type (IEC_TIMER for a TON_TIME instance)
    referenced_type: str | None = None

    @property
    def element_type(self) -> str:
        """The type of this member, or of each element of this array member, without the array bounds or quotes.

        It names a UDT or FB, a library type such as ``IEC_TIMER`` and an elementary type such as ``Int`` alike.
        """
        # only a leading prefix makes an array: elsewhere it is part of a quoted name
        prefix = _ARRAY_PREFIX.match(self.data_type)
        return self.data_type[prefix.end() if prefix else 0 :].strip('"')


@dataclass
class BlockInterface:
    """A parsed ``<BlockInterface>`` document: its members and the blocks it is built from.

    Attributes:
        members: The block's top-level members, as :func:`parse_block_interface` returns them.
        source: The FB an instance DB copies its interface from, or None for any
            other interface. The FB is embedded in the instance DB's interface, so a
            library FB has a source too. A DB declared of a UDT has none, and neither
            does the instance DB of a system type such as ``IEC_TIMER``: the
            interface only references the type, so the DB has no members and the
            type is in `references`.
        references: Names of the other types the interface mentions: the ``Block``
            of every ``<Part>``, every ``<ExternalType>`` and every UDT or FB a
            member ``Type`` quotes, array element types included. A member ``Type``
            that names a UDT without quotes is not listed unless a ``<Part>`` or
            ``<ExternalType>`` also names it. The block's own name is left out, and
            so is the FB of an instance DB that has a `source`: it is there instead, so a caller
            exploring the blocks an interface is built from needs both. Besides the
            program's UDTs and FBs, it holds the library and system types the interface
            references without embedding, such as ``IEC_TIMER``; these are not blocks of
            the program, and they are the names :attr:`Member.referenced_type` gives.
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
            BlockInterfaceError: The text is not well-formed XML.
            ValueError: The interface exceeds the limits of :func:`parse_block_interface`.
        """
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise BlockInterfaceError(f"Block interface XML is not well-formed: {exc}") from exc
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
    # FB, FC and OB: Root holds one header per section, in declaration order. A header holds its
    # variables itself (OB start info, FC Return, library FBs) or selects the <Part Kind="*Section">
    # holding them; a block may mix both.
    read: set[int] = set()
    for header in part.findall("./Payload/Root/Member"):
        if header.get("RID") is not None:
            continue
        members += _build_members([header], header.get("Name", ""), subparts, seen, limits)
        target = _subpart(header, subparts, seen)
        kind = "" if target is None else target.get("Kind", "")
        if target is not None and id(target) not in read and kind.endswith("Section"):
            read.add(id(target))
            members += _build_members(target.findall("./Payload/Member"), kind[: -len("Section")], subparts, seen, limits)
    # a section part no header selects (corrupt SubPartIndex) is still read, after the declared ones
    for sp in subparts:
        kind = sp.get("Kind", "")
        if id(sp) not in read and kind.endswith("Section"):
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
        # a referenced, not embedded, type is a part with a Block but no Kind
        referenced_type=None if target is None or target.get("Kind") else target.get("Block") or None,
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
    DB/UDT, or for an FB/OB from the section headers there, which hold the
    variables of an OB, FC or library FB themselves, and from the
    ``<Part Kind="*Section">`` entries. Members are returned in declaration
    order: a DB's or UDT's as ``<Root>`` lists them, an FB's, FC's or OB's
    section by section as the section headers in ``<Root>`` list them, each
    tagged with its section (Input/Output/... for FB/FC/OB; empty for DB/UDT).
    A ``*Section`` part that no header selects is read after the declared
    sections. Named constants are returned in the ``Constant`` section, so their
    ``LineComm`` comments resolve, but they have no value to read: the PLC
    refuses a read of a constant's LID.

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
        BlockInterfaceError: The text is not well-formed XML.
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
    continues in the members `types` holds for its :attr:`Member.referenced_type`,
    or for its :attr:`Member.element_type` when it has none, and a path below a
    type that is in neither is not resolved.

    Example::

        interface = BlockInterface.from_xml(xml_text)
        resolve_id_path(interface.members, "60:51[2]")  # "motor.speeds[2]"

    Args:
        members: Member tree of the block the path starts in.
        id_path: Colon-joined path as written in a ``<Comment Path="...">``.
        types: Members of the types the interface did not embed, by the names
            :attr:`BlockInterface.references` gives them: the interface of a UDT,
            FB or system type explored on its own, such as ``IEC_TIMER``.

    Returns:
        The dotted name path, or None when a segment is malformed or names no member.
    """
    names: list[str] = []
    for segment in id_path.split(":"):
        matched = _ID_PATH_SEGMENT.fullmatch(segment)
        if matched is None:
            return None
        member_id = int(matched.group(1))
        # 0 marks a member without an ID, so it names none
        entry = next((member for member in members if member_id and member.id == member_id), None)
        if entry is None:
            return None
        prefix = _ARRAY_PREFIX.match(entry.data_type)
        # an element needs one index per dimension ("Array[0..1, 0..2] of" has 2); no index names the whole member
        dimensions = prefix.group().count(",") + 1 if prefix else 0
        index = matched.group(2) or ""
        if index and index.count(",") + 1 != dimensions:
            return None
        names.append(entry.name + index)
        # an embedded type carries its own ids; only a missing one needs the caller's types.
        # An inline Struct is always embedded, so an empty one must not be looked up there;
        # its type is unquoted, unlike a UDT that happens to be named "Struct".
        if entry.fields or entry.data_type[prefix.end() if prefix else 0 :] == "Struct":
            members = entry.fields
        else:
            members = (types or {}).get(entry.referenced_type or entry.element_type, ())
    return ".".join(names)
