"""Parse symbolic tags and the data-block list from S7CommPlus EXPLORE responses.

S7-1200/1500 PLCs answer an EXPLORE request with a zlib blob compressed
against a Siemens preset dictionary. Once decompressed with
:func:`s7commplus.blob_decompressor.decompress_blob`, the payload is clean
XML. The I/Q/M areas answer with an ``<IdentContainer>`` whose ``<Ident>``
entries carry a direct ``<SimpleType>`` and ``<SimpleAccess>`` address (dict
``IntfDescTag`` / Adler-32 ``0xce9b821b``), parsed into :class:`Tag`.

Block interfaces (``<BlockInterface>``) are parsed in
:mod:`s7commplus.block_interface`; their names are re-exported here so imports
from this module keep working.

Validated end-to-end against a live S7-1200 G2 (FW V4.1): I/Q/M tags and an
optimized DB (``Data_block_1``, 11 members, names + Bool/Int/Real types).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass

from .blob_decompressor import find_preset_stream, decompress_blob
from .block_interface import SOFTDATATYPE, Member, block_interface_from_explore, parse_block_interface

__all__ = [
    "AREA_RID",
    "SOFTDATATYPE",
    "DataBlock",
    "Member",
    "Tag",
    "block_interface_from_explore",
    "datablocks_from_explore",
    "parse_block_interface",
    "parse_ident_container",
    "tags_from_explore",
]

# EXPLORE relation IDs per area (S7-1200 V3 / FW V4.x).
AREA_RID = {"I": 80, "Q": 81, "M": 82}
# Preset-dict kind of the I/Q/M symbols.
_IDENT_KIND = "IntfDescTag"

# <SimpleAccess Range="..."> -> TIA area letter.
_RANGE_LETTER = {"Input": "I", "Output": "Q", "Memory": "M"}
# <SimpleAccess Width="..."> -> TIA address suffix for non-bit widths.
_WIDTH_SUFFIX = {"Byte": "B", "Word": "W", "DWord": "D", "LWord": "L"}


@dataclass
class Tag:
    """A symbolic I/Q/M tag resolved from an EXPLORE response."""

    name: str
    data_type: str  # <SimpleType>, e.g. Bool / Byte / Word / DWord
    address: str  # TIA syntax, e.g. %I0.0 / %MB100 / %MW102
    lid: int
    byte_offset: int
    bit_offset: int | None


def _address(rng: str, width: str, byte_no: int, bit_no: int | None) -> str:
    letter = _RANGE_LETTER.get(rng, "?")
    if width == "Bit":
        return f"%{letter}{byte_no}.{bit_no or 0}"
    return f"%{letter}{_WIDTH_SUFFIX.get(width, '')}{byte_no}"


def parse_ident_container(xml_text: str) -> list[Tag]:
    """Parse a decompressed ``<IdentContainer>`` document into :class:`Tag`s."""
    tags: list[Tag] = []
    for ident in ET.fromstring(xml_text).findall("Ident"):
        acc = ident.find("./Access/SimpleAccess")
        if acc is None:
            continue  # only SimpleAccess idents carry a direct I/Q/M address
        byte_no = int(acc.get("ByteNumber", "0"))
        bit_raw = acc.get("BitNumber")
        bit_no = int(bit_raw) if bit_raw is not None else None
        tags.append(
            Tag(
                name=ident.get("Name", ""),
                data_type=ident.findtext("SimpleType", default=""),
                address=_address(acc.get("Range", ""), acc.get("Width", ""), byte_no, bit_no),
                lid=int(ident.get("LID", "0")),
                byte_offset=byte_no,
                bit_offset=bit_no,
            )
        )
    return tags


def tags_from_explore(explore_payload: bytes) -> list[Tag]:
    """Decompress a raw I/Q/M EXPLORE payload and parse its symbolic tags.

    Returns an empty list if the payload contains no preset-dict zlib stream.

    Raises:
        ValueError: If the stream does not decompress or is not well-formed XML.
    """
    pos = find_preset_stream(explore_payload, (_IDENT_KIND,))
    if pos is None:
        return []
    try:
        return parse_ident_container(decompress_blob(explore_payload, offset=pos))
    except (zlib.error, ET.ParseError) as exc:
        raise ValueError(f"Tag EXPLORE payload is corrupt: {exc}") from exc


def _find_zlib_stream(data: bytes) -> int | None:
    """Return the offset of the first standard (non-preset) zlib stream.

    Standard-compression ``PlcContentInfo`` uses CMF ``0x78`` but its FLG byte
    varies with the compression level (``78 01`` / ``78 5e`` / ``78 9c`` /
    ``78 da``). Match any ``0x78`` whose 2-byte header checksums correctly
    (``CMF*256 + FLG`` divisible by 31) and has no preset-dict flag set, rather
    than hardcoding a single FLG value.
    """
    for i in range(len(data) - 1):
        if data[i] == 0x78 and not (data[i + 1] & 0x20) and ((data[i] << 8) | data[i + 1]) % 31 == 0:
            return i
    return None


@dataclass
class DataBlock:
    """A data block advertised in the PlcContentInfo listing."""

    name: str
    number: int
    rid: int


def datablocks_from_explore(wildcard_payload: bytes) -> list[DataBlock]:
    """Parse the DB list from a ``0x8A11FFFF`` wildcard EXPLORE response.

    PlcContentInfo is a *standard* zlib stream embedded in a larger BLOB, so it
    is raw-inflated (the Adler-32 trailer would fail on the trailing bytes). The
    stream header is located tolerantly (any compression level), not assumed to
    be ``78 da``. Returns only ``Type="DB"`` blocks.

    Raises:
        ValueError: If the stream inflates to something that is not well-formed XML.
    """
    pos = _find_zlib_stream(wildcard_payload)
    if pos is None:
        return []
    try:
        xml_bytes = zlib.decompressobj(wbits=-15).decompress(wildcard_payload[pos + 2 :])
    except zlib.error:
        return []
    try:
        root = ET.fromstring(xml_bytes.decode("utf-8"))
    except ET.ParseError as exc:
        raise ValueError(f"Data block list EXPLORE payload is not well-formed XML: {exc}") from exc
    dbs: list[DataBlock] = []
    for entity in root.findall('.//Entity[@Id="Block"]'):
        header = entity.find("Header")
        if header is None or header.get("Type") != "DB":
            continue
        try:
            dbs.append(
                DataBlock(
                    name=header.get("Name", ""),
                    number=int(header.get("Number", "0")),
                    rid=int(entity.get("Rid", "0")),
                )
            )
        except ValueError:
            continue
    return dbs
