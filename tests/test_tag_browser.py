"""Tests for the symbolic tag browser.

The I/Q/M fixture is a real preset-dictionary EXPLORE blob captured from a live
S7-1200 G2 (FW V4.1) M area (``IntfDescTag`` dict, Adler-32 ``0xce9b821b``).
Block interfaces are tested in ``test_block_interface.py``.
"""

import base64
import zlib

import pytest

from s7commplus.block_interface import _INTFDESC_KINDS
from s7commplus.tag_browser import (
    DataBlock,
    Tag,
    _IDENT_KIND,
    datablocks_from_explore,
    parse_ident_container,
    tags_from_explore,
)
from s7commplus.zlib_dicts import ZLIB_DICT_IDENTITIES

# Live S7-1200 G2 (FW V4.1) EXPLORE response for the M area, from the zlib
# header onward: b"\x78\x7d" + dict-adler(0xce9b821b) + raw deflate.
_M_AREA_BLOB = base64.b64decode(
    "eH3Om4Ibs7GvyM1RKEstKs7MzwNmJj1gMZCal5yfkpmXbqtUWpKma6Fkb2eDrgs5AHJTi7JTi2hVgOG"
    "MSCNiii8sgQEPChQ/lABjMQloHHZPGBqi+QKokhJfIBdfBkguBzuAHKeXg1MAVqejlWCgtEI1pxthL3t"
    "JcnoKHrejFWEuVHW8CfEZCE+aAaZnHI43o1XKN1BC84kFyWkfvRgAACgQWbajk3JAFAIAOJgAAAJ4fe"
    "JynqGzsa/IzVEoSy0qBgoAvatnoKSQmpecn5KZl26rVFqSpmuhZI/NBiLNBwAy/SHEAKKiogAAAAA="
)


def test_parse_ident_container_addresses():
    xml = (
        "<IdentContainer>"
        '<Ident Name="input_1" Scope="Global" LID="10"><SimpleType>Bool</SimpleType>'
        '<Access SubClass="SimpleAccess"><SimpleAccess BitNumber="0" ByteNumber="0"'
        ' Width="Bit" Range="Input" /></Access></Ident>'
        '<Ident Name="mtag_word" Scope="Global" LID="13"><SimpleType>Word</SimpleType>'
        '<Access SubClass="SimpleAccess"><SimpleAccess ByteNumber="102"'
        ' Width="Word" Range="Memory" /></Access></Ident>'
        "</IdentContainer>"
    )
    tags = parse_ident_container(xml)
    assert tags == [
        Tag("input_1", "Bool", "%I0.0", 10, 0, 0),
        Tag("mtag_word", "Word", "%MW102", 13, 102, None),
    ]


def test_tags_from_live_g2_m_area():
    tags = tags_from_explore(_M_AREA_BLOB)
    got = {t.name: (t.data_type, t.address) for t in tags}
    assert got == {
        "merker_1": ("Bool", "%M0.2"),
        "mtag_byte": ("Byte", "%MB100"),
        "mtag_word": ("Word", "%MW102"),
        "mtag_dword": ("DWord", "%MD104"),
        "mtag_bool": ("Bool", "%M108.0"),
    }


def test_tags_from_explore_no_stream_returns_empty():
    assert tags_from_explore(b"no zlib stream here") == []


def test_tags_from_explore_raises_on_corrupt_stream():
    # iter_preset_streams skips undecodable streams; tag_browser must surface them instead.
    # IntfDescTag header followed by an invalid deflate block.
    payload = bytes.fromhex("787d ce9b821b") + b"\xff" * 8
    with pytest.raises(ValueError) as caught:
        tags_from_explore(payload)
    assert isinstance(caught.value.__cause__, zlib.error)


@pytest.mark.parametrize("kind", [_IDENT_KIND, *_INTFDESC_KINDS])
def test_tag_browser_kinds_have_one_dictionary(kind: str):
    # Matching is by kind alone; a second version would reach the parser unreviewed.
    # Check that the parser handles its layout, then update this test.
    assert sum(p.kind == kind for p in ZLIB_DICT_IDENTITIES.values()) == 1


def test_datablocks_from_explore_standard_zlib():
    # PlcContentInfo is a standard zlib stream (78 da) embedded in a larger BLOB;
    # trailing bytes follow it, so decoding must raw-inflate and tolerate them.
    xml = (
        b'<?xml version="1.0" encoding="utf-8"?><PlcContentInfo>'
        b'<Entity Id="Block" Rid="2316173337"><Header Name="Data_block_1"'
        b' Number="25" Type="DB" /></Entity>'
        b'<Entity Id="Block" Rid="2316435466"><Header Name="FB_Macchina"'
        b' Number="10" Type="FB" /></Entity>'
        b"</PlcContentInfo>"
    )
    stream = zlib.compress(xml, 9)  # -> 78 da header
    assert stream[:2] == b"\x78\xda"
    payload = b"\x00\x01prefix" + stream + b"trailing-blob-bytes\xff\x00"
    assert datablocks_from_explore(payload) == [
        DataBlock("Data_block_1", 25, 2316173337),
    ]


def test_datablocks_from_explore_no_stream_returns_empty():
    assert datablocks_from_explore(b"no zlib here") == []
