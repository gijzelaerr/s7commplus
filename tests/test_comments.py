"""Tests for resolving TIA comments onto browse() names, offline and against the server emulator."""

import base64
import logging
import re
import struct
from collections.abc import Callable, Generator, Iterable
from itertools import combinations
from unittest.mock import patch

import pytest

from s7commplus import AsyncClient, Client, CommentCollector, Comments, ProgramObject, Server
from s7commplus.blob_decompressor import PresetStream, _compress_blob, iter_preset_streams
from s7commplus.client import _build_explore_request
from s7commplus.codec import encode_pvalue_blob
from s7commplus.comments import _BlockComments
from s7commplus.error import S7ReturnValueError
from s7commplus.protocol import DataType, ElementID, FunctionCode, Ids
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq
from s7commplus.zlib_dicts import ZLIB_DICT_IDENTITIES

INTERFACE = 0x66052B13  # DebugInfo IntfDesc
LINE_COMMENTS = 0x3C55436A  # LineComm
TAG_INTERFACE = 0xCE9B821B  # IntfDescTag
TAG_COMMENTS = 0xE2729EA1  # TagLineComm

DB1, DB2, DB3 = 0x8A0E0001, 0x8A0E0002, 0x8A0E0003
PUMP, IDLE, MOTOR, STRUCT_UDT = 0x8A120001, 0x8A120002, 0x89FD0001, 0x89FD0002

# DB1: an Int, a member of the UDT "Motor" that the interface does not embed, an array and an inline Struct
DB1_INTERFACE = (
    '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
    '<Member ID="51" Name="level" RID="0x02000005" LID="1" StdO="0" />'
    '<Member ID="52" Name="motor" RID="0x91000001" Type=\'"Motor"\' LID="2" StdO="2" />'
    '<Member ID="53" Name="limits" RID="0x02010005" Type="Array[0..2] of Int" LID="3" StdO="6" />'
    '<Member ID="54" Name="cfg" RID="0x00000000" SubPartIndex="0" LID="4" StdO="12" />'
    '</Root></Payload><SubParts><Part Kind="Structure"><Payload><Member>'
    '<Member ID="51" Name="gain" RID="0x02000008" LID="5" StdO="12" />'
    "</Member></Payload></Part></SubParts></Part></BlockInterface>"
)
# The DB's own comment on motor.speed wins over the one the UDT carries
DB1_LINE_COMMENTS = (
    '<InterfaceLineComments><Part Kind="Comments">'
    '<Comment Path="51"><DictEntry Language="en-US">Tank level</DictEntry>'
    '<DictEntry Language="de-DE">Füllstand</DictEntry></Comment>'
    '<Comment Path="53"><DictEntry Language="en-US">Limits</DictEntry></Comment>'
    '<Comment Path="54:51"><DictEntry Language="en-US">Gain</DictEntry></Comment>'
    '<Comment Path="52:51"><DictEntry Language="en-US">Plant motor speed</DictEntry></Comment>'
    '<Comment Path="99"><DictEntry Language="en-US">No such member</DictEntry></Comment>'
    "</Part></InterfaceLineComments>"
)
MOTOR_SOURCE = (
    '<Part Kind="DataTypeSource" Block="Motor"><Payload><Root>'
    '<Member ID="51" Name="speed" RID="0x02000008" LID="1" StdO="0" />'
    '<Member ID="52" Name="current" RID="0x02000008" LID="2" StdO="4" />'
    "</Root></Payload></Part>"
)
MOTOR_INTERFACE = f"<BlockInterface>{MOTOR_SOURCE}</BlockInterface>"
MOTOR_LINE_COMMENTS = (
    '<InterfaceLineComments><Part Kind="Comments">'
    '<Comment Path="51"><DictEntry Language="en-US">Motor speed</DictEntry>'
    '<DictEntry Language="de-DE">Drehzahl</DictEntry></Comment>'
    '<Comment Path="52"><DictEntry Language="en-US">Motor current</DictEntry></Comment>'
    "</Part></InterfaceLineComments>"
)
# DB3 is declared of the UDT "Motor" and overrides one language of its speed comment
DB3_INTERFACE = f'<BlockInterface><Part Kind="Values" Block="DB3"><SubParts>{MOTOR_SOURCE}</SubParts></Part></BlockInterface>'
DB3_LINE_COMMENTS = (
    '<InterfaceLineComments><Part Kind="Comments">'
    '<Comment Path="51"><DictEntry Language="de-DE">Pumpendrehzahl</DictEntry></Comment>'
    "</Part></InterfaceLineComments>"
)
PUMP_SOURCE = (
    '<Part Kind="BlockSource" Block="Pump"><Payload><Root>'
    '<Member ID="5" Name="Static" SubPartIndex="0" StdO="0" />'
    '</Root></Payload><SubParts><Part Kind="StaticSection"><Payload><Member>'
    '<Member ID="51" Name="running" RID="0x02000001" LID="1" StdO="0" />'
    "</Member></Payload></Part></SubParts></Part>"
)
PUMP_INTERFACE = f"<BlockInterface>{PUMP_SOURCE}</BlockInterface>"
# DB2 is an instance of the FB "Pump": it repeats the FB's interface, but none of its comments
DB2_INTERFACE = f'<BlockInterface><Part Kind="Values" Block="DB2"><SubParts>{PUMP_SOURCE}</SubParts></Part></BlockInterface>'
PUMP_LINE_COMMENTS = (
    '<InterfaceLineComments><Part Kind="Comments">'
    '<Comment Path="51"><DictEntry Language="en-US">Pump running</DictEntry></Comment>'
    "</Part></InterfaceLineComments>"
)
# A UDT named "Struct", which TIA accepts: the inline Struct DB1.cfg is not typed with it, so must not take its comment
STRUCT_UDT_INTERFACE = (
    '<BlockInterface><Part Kind="DataTypeSource" Block="Struct"><Payload><Root>'
    '<Member ID="51" Name="x" RID="0x02000005" LID="1" StdO="0" />'
    "</Root></Payload></Part></BlockInterface>"
)
STRUCT_UDT_LINE_COMMENTS = (
    '<InterfaceLineComments><Part Kind="Comments">'
    '<Comment Path="51"><DictEntry Language="en-US">UDT Struct x</DictEntry></Comment>'
    "</Part></InterfaceLineComments>"
)
# A tag typed with a UDT has <UserDataType> in place of <SimpleType>, as the I/Q areas of the .51 S7-1500 send it
I_AREA_TAGS = (
    '<IdentContainer><Ident Name="Start" LID="7"><SimpleType>Bool</SimpleType></Ident><Ident Name="Stop" LID="8" />'
    '<Ident Name="Drive" LID="9"><UserDataType>Motor</UserDataType></Ident></IdentContainer>'
)
I_AREA_TAG_COMMENTS = (
    "<CommentDictionary><TagLineComments>"
    '<Comment RefID="7"><DictEntry Language="en-US">Start button</DictEntry></Comment>'
    "</TagLineComments></CommentDictionary>"
)


def compress_blob(xml: str, dictionary: int) -> bytes:
    return _compress_blob(xml, ZLIB_DICT_IDENTITIES[dictionary])


@pytest.fixture()
def documents() -> dict[int, list[tuple[int, str]]]:
    return {
        DB1: [(INTERFACE, DB1_INTERFACE), (LINE_COMMENTS, DB1_LINE_COMMENTS)],
        DB2: [(INTERFACE, DB2_INTERFACE)],
        DB3: [(INTERFACE, DB3_INTERFACE), (LINE_COMMENTS, DB3_LINE_COMMENTS)],
        PUMP: [(INTERFACE, PUMP_INTERFACE), (LINE_COMMENTS, PUMP_LINE_COMMENTS)],
        MOTOR: [(INTERFACE, MOTOR_INTERFACE), (LINE_COMMENTS, MOTOR_LINE_COMMENTS)],
        STRUCT_UDT: [(INTERFACE, STRUCT_UDT_INTERFACE), (LINE_COMMENTS, STRUCT_UDT_LINE_COMMENTS)],
        Ids.NATIVE_THE_I_AREA_RID: [(TAG_INTERFACE, I_AREA_TAGS), (TAG_COMMENTS, I_AREA_TAG_COMMENTS)],
    }


@pytest.fixture()
def payloads(documents: dict[int, list[tuple[int, str]]]) -> dict[int, bytes]:
    return {rid: b"\x00\x01".join(compress_blob(xml, dictionary) for dictionary, xml in docs) for rid, docs in documents.items()}


@pytest.fixture()
def objects() -> list[ProgramObject]:
    return [
        ProgramObject(DB1, Ids.DB_CLASS_RID, "DB1"),
        ProgramObject(DB2, Ids.DB_CLASS_RID, "DB2"),
        ProgramObject(DB3, Ids.DB_CLASS_RID, "DB3"),
        ProgramObject(PUMP, Ids.FB_CLASS_RID, "Pump"),
        ProgramObject(IDLE, Ids.FB_CLASS_RID, "Idle"),
        ProgramObject(MOTOR, Ids.UDT_CLASS_RID, "Motor"),
        ProgramObject(STRUCT_UDT, Ids.UDT_CLASS_RID, "Struct"),
        ProgramObject(Ids.NATIVE_THE_PLC_PROGRAM_RID, Ids.PLC_PROGRAM_CLASS_RID, "PLCProgram"),
    ]


def _program_reply(objects: list[ProgramObject], payloads: dict[int, bytes]) -> bytes:
    """An EXPLORE reply of the program: every object below PLCProgram with its name and its documents as one BLOB."""
    names = {obj.rid: obj.name for obj in objects if obj.rid != Ids.NATIVE_THE_PLC_PROGRAM_RID}
    classes = {obj.rid: obj.class_id for obj in objects}

    def start(rid: int, class_id: int, name: str | None) -> bytes:
        obj = bytes([ElementID.START_OF_OBJECT]) + struct.pack(">I", rid) + encode_uint32_vlq(class_id) + b"\x00\x00"
        if name is None:  # a process area
            return obj
        encoded = name.encode("utf-16-be")
        return (
            obj
            + bytes([ElementID.ATTRIBUTE])
            + encode_uint32_vlq(Ids.OBJECT_VARIABLE_TYPE_NAME)
            + bytes([0x00, DataType.WSTRING])
            + encode_uint32_vlq(len(encoded))
            + encoded
        )

    reply = encode_uint64_vlq(0) + start(Ids.NATIVE_THE_PLC_PROGRAM_RID, Ids.PLC_PROGRAM_CLASS_RID, "PLCProgram")
    for rid in {**names, **payloads}:
        reply += start(rid, classes.get(rid, 0), names.get(rid))
        if rid in payloads:
            reply += bytes([ElementID.ATTRIBUTE]) + encode_uint32_vlq(Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION)
            reply += encode_pvalue_blob(payloads[rid])
        reply += bytes([ElementID.TERMINATING_OBJECT])
    return reply + bytes([ElementID.TERMINATING_OBJECT]) + struct.pack(">I", 0)


def _collect(objects: list[ProgramObject], payloads: dict[int, bytes]) -> CommentCollector:
    return CommentCollector(_program_reply(objects, payloads))


def test_block_comments_keep_every_language_and_merge_a_repeated_document(payloads: dict[int, bytes]):
    payload = payloads[DB1] + compress_blob(DB1_LINE_COMMENTS, LINE_COMMENTS) + compress_blob("<IdentES />", 0x5814B03B)

    block = _BlockComments.for_block(iter_preset_streams(payload))

    assert [member.name for member in block.interface.members] == ["level", "motor", "limits", "cfg"]
    assert block.interface.references == frozenset({"Motor"})
    assert block.line_comments["51"] == {"en-US": "Tank level", "de-DE": "Füllstand"}
    assert len(block.line_comments) == 5


def test_block_comments_join_process_area_comments_by_lid(payloads: dict[int, bytes]):
    block = _BlockComments.for_area(iter_preset_streams(payloads[Ids.NATIVE_THE_I_AREA_RID]))

    assert [(tag.name, tag.id, tag.typed_block) for tag in block.interface.members] == [
        ("Start", 7, None),
        ("Stop", 8, None),
        ("Drive", 9, "Motor"),
    ]
    assert block.interface.references == frozenset({"Motor"})
    assert block.line_comments == {"7": {"en-US": "Start button"}}


def test_block_comments_without_documents_are_empty():
    block = _BlockComments.for_block(iter_preset_streams(b"\x00\x01\x02"))

    assert (block.interface.members, block.line_comments) == ([], {})


@pytest.mark.parametrize(
    ("parse", "dictionary"),
    [
        (_BlockComments.for_block, INTERFACE),
        (_BlockComments.for_block, LINE_COMMENTS),
        (_BlockComments.for_area, TAG_INTERFACE),
        (_BlockComments.for_area, TAG_COMMENTS),
    ],
)
def test_block_comments_reject_malformed_xml(parse: Callable[[Iterable[PresetStream]], _BlockComments], dictionary: int):
    with pytest.raises(ValueError, match="not well-formed"):
        parse(iter_preset_streams(compress_blob("<Comment", dictionary)))


@pytest.mark.parametrize("dictionary", [INTERFACE, LINE_COMMENTS])
def test_block_comments_reject_a_truncated_document(dictionary: int):
    stream = compress_blob(DB1_INTERFACE if dictionary == INTERFACE else DB1_LINE_COMMENTS, dictionary)

    with pytest.raises(ValueError, match="not well-formed"):
        _BlockComments.for_block(iter_preset_streams(stream[: len(stream) // 2]))


def test_block_comments_ignore_a_header_cut_short():
    block = _BlockComments.for_block(iter_preset_streams(compress_blob(DB1_LINE_COMMENTS, LINE_COMMENTS)[:4]))

    assert (block.interface.members, block.line_comments) == ([], {})


def test_block_comments_skip_and_log_entries_without_key(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG, logger="s7commplus.comments")
    xml = (
        "<InterfaceLineComments>"
        '<Comment UId="1" RefID="10"><DictEntry Language="en-US">GRAPH7_INTERLOCK_ERROR</DictEntry></Comment>'
        '<Comment Path="51"><DictEntry Language="en-US">kept</DictEntry></Comment>'
        "</InterfaceLineComments>"
    )

    assert _BlockComments.for_block(iter_preset_streams(compress_blob(xml, LINE_COMMENTS))).line_comments == {
        "51": {"en-US": "kept"}
    }
    assert "Skipping 1 comments without a Path attribute" in caplog.text


def test_collector_resolves_data_blocks_and_areas_with_the_blocks_they_are_built_from(
    objects: list[ProgramObject], payloads: dict[int, bytes]
):
    collector = _collect(objects, payloads)

    assert dict(collector.resolve()) == {
        "DB1.level": "Tank level",
        "DB1.limits": "Limits",
        "DB1.cfg.gain": "Gain",
        "DB1.motor.speed": "Plant motor speed",
        "DB1.motor.current": "Motor current",
        "DB2.running": "Pump running",
        "DB3.speed": "Motor speed",
        "DB3.current": "Motor current",
        "IArea.Start": "Start button",
        "IArea.Drive.speed": "Motor speed",
        "IArea.Drive.current": "Motor current",
    }


def test_collector_resolves_a_db_named_like_a_process_area_and_the_area(objects: list[ProgramObject], payloads: dict[int, bytes]):
    # regression: the area replaced the DB of its name
    objects[0] = ProgramObject(DB1, Ids.DB_CLASS_RID, "IArea")

    collector = _collect(objects, payloads)

    # browse() names the tags of both IArea, so the comments of both are under that name
    assert {name: text for name, text in collector.resolve().items() if name.startswith("IArea.")} == {
        "IArea.level": "Tank level",
        "IArea.limits": "Limits",
        "IArea.cfg.gain": "Gain",
        "IArea.motor.speed": "Plant motor speed",
        "IArea.motor.current": "Motor current",
        "IArea.Start": "Start button",
        "IArea.Drive.speed": "Motor speed",
        "IArea.Drive.current": "Motor current",
    }


def test_collector_rejects_a_program_payload_cut_inside_an_object():
    # ReturnValue 0, then a StartOfObject whose RelationId is cut short
    with pytest.raises(ValueError, match="truncated or malformed"):
        CommentCollector(bytes([0x00, 0xA1, 0x8A, 0x0E]))


def test_collector_resolves_a_db_declared_of_a_udt_and_keeps_the_languages_it_does_not_override(
    objects: list[ProgramObject], payloads: dict[int, bytes]
):
    comments = _collect(objects, payloads).resolve()

    assert comments.languages("DB3.speed") == {"en-US": "Motor speed", "de-DE": "Pumpendrehzahl"}
    assert comments.languages("DB1.motor.speed") == {"en-US": "Plant motor speed", "de-DE": "Drehzahl"}


@pytest.fixture()
def nested_udts() -> tuple[list[ProgramObject], dict[int, bytes]]:
    """DB1 has a member of the UDT A, which has one of B, which has one of A again."""
    a = '<BlockInterface><Part Kind="DataTypeSource" Block="A"><Payload><Root><Member ID="51" Name="b" RID="0x91000001" Type=\'"B"\' /></Root></Payload></Part></BlockInterface>'
    b = '<BlockInterface><Part Kind="DataTypeSource" Block="B"><Payload><Root><Member ID="51" Name="a" RID="0x91000001" Type=\'"A"\' /></Root></Payload></Part></BlockInterface>'
    db = '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root><Member ID="51" Name="x" RID="0x91000001" Type=\'"A"\' /></Root></Payload></Part></BlockInterface>'
    comment = (
        '<InterfaceLineComments><Comment Path="51"><DictEntry Language="en-US">{}</DictEntry></Comment></InterfaceLineComments>'
    )
    payloads = {
        DB1: compress_blob(db, INTERFACE),
        0x89FD0001: compress_blob(a, INTERFACE) + compress_blob(comment.format("A.b"), LINE_COMMENTS),
        0x89FD0002: compress_blob(b, INTERFACE) + compress_blob(comment.format("B.a"), LINE_COMMENTS),
    }
    objects = [
        ProgramObject(DB1, Ids.DB_CLASS_RID, "DB1"),
        ProgramObject(0x89FD0001, Ids.UDT_CLASS_RID, "A"),
        ProgramObject(0x89FD0002, Ids.UDT_CLASS_RID, "B"),
    ]
    return objects, payloads


def test_collector_ends_on_blocks_that_reference_each_other(nested_udts: tuple[list[ProgramObject], dict[int, bytes]]):
    collector = _collect(*nested_udts)

    # The recursion stops where B's member a is typed with A again, which is still being resolved
    assert dict(collector.resolve()) == {"DB1.x.b": "A.b", "DB1.x.b.a": "B.a"}


def test_collector_limits_how_deep_blocks_nest(nested_udts: tuple[list[ProgramObject], dict[int, bytes]]):
    collector = _collect(*nested_udts)

    assert len(collector.resolve(max_depth=2)) == 2
    with pytest.raises(ValueError, match="deeper than 1 levels"):
        collector.resolve(max_depth=1)


def test_collector_copies_the_comments_of_a_type_named_by_its_referenced_type():
    # regression: t is typed "Alias", but the part it points at names the block Lib, which holds the comments
    db = (
        '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
        '<Member ID="51" Name="t" RID="0x91000001" Type=\'"Alias"\' SubPartIndex="0" />'
        '</Root></Payload><SubParts><Part Block="Lib" /></SubParts></Part></BlockInterface>'
    )
    lib = '<BlockInterface><Part Kind="BlockSource" Block="Lib"><Payload><Root><Member ID="51" Name="x" RID="0x02000005" /></Root></Payload></Part></BlockInterface>'
    lib_comments = '<InterfaceLineComments><Comment Path="51"><DictEntry Language="en-US">From Lib</DictEntry></Comment></InterfaceLineComments>'
    payloads = {
        DB1: compress_blob(db, INTERFACE),
        MOTOR: compress_blob(lib, INTERFACE) + compress_blob(lib_comments, LINE_COMMENTS),
    }
    objects = [ProgramObject(DB1, Ids.DB_CLASS_RID, "DB1"), ProgramObject(MOTOR, Ids.FB_CLASS_RID, "Lib")]

    assert dict(_collect(objects, payloads).resolve()) == {"DB1.t.x": "From Lib"}


# Live S7-1500 (FW V2.9) EXPLORE replies, each cut to one block's interface stream and the LineComm
# stream after it. DB_StructUdt (DB 38) has m : "Struct" and a : Array[0..1] of "Struct", where "Struct"
# is a UDT with one Int x; every member's comment is its own path.
_DB_STRUCT_UDT_BLOB = base64.b64decode(
    "eH1mBSsTpVfbbhMxEP2V1SLx5sbjuwOJ1CSVQAJV4vZAVSHveo2QgBRaUD6fsb272UuqUshL9uKd"
    "Gc+cOWf8MDOaOTGOC7IeKVCxyBrU1m63yYyHYM8VYohBdxjCQ+ZHfTsDhrB9s12VQmgDXCroEdBK"
    "yarcvPxwsdxtPuVB5b2/W4DnXFmhCbWhIgKqmhhqHKlp4BoCrb2vWvaJk1JzuGOrMmcUkyzizIOS"
    "kR8ZGpPfrk5IoQebysFUkuOcRcsMRr73zddV+YEhodOMpbbFWuMAPBpvMy9ML2Vxi/SwEVrJHYdu"
    "6No1N7E0LNfoVfP9c7wVmOV3P5HWsCxF/Qs7pgneWi0caTQoIiqnSSW8J5ZBLblWDCjDj158uY04"
    "KaJrSVWjq0CkpUCEtYo45hyxlbGmFsp75spYvkXnaX0kgKhIUy43Fa+1ppa4UHEihKfEeeWJ4ZVv"
    "uDNeSlEOJCJCpZtcbtejIWZCEbSDc85JV7dIl6sSp+gWIPQg6HZ3Ic9hmlRuzqncRodZwzPeJXR2"
    "v6WNjt6x7l2bhGF4g1sMvCWeiIuRxQ4pkOq+6Yjl6Y9f+7tneSf5esqINAHkMl0kSrIphKGfYXSd"
    "Hzv2kxTmip6dwXWxD8Uj3OLwk/3G1kPH7dxU3A5R+3sE+x7jCd5TLK+zMMX19xgxNN2MzeAkd+yd"
    "FMm+2K9Kzo7X0UisThtiRtH3yA2YrQj0/lCW3ADNdhYRv/jX47krZz/ZDQA5T9OssmN09nT4KfFS"
    "frwIuvK42hEO1hGBnYId6jihddVoITVn3oyhNgymn7FGbIpsH4s94VSYcyqMOdW2NQJqNONSGDvn"
    "1H8I/h46pdC+OqZodnZEikM2JQBI2O+oXnK9FPxMG8YUYx9PHEEf+qAfhf72g8vXb29iMv96/ehs"
    "8tDqkXb0uHlQLehILWJjXt7cDW7uYbmJNnAmHJWCBBOJWduGmLquiaPgfF1LoRo+1gYIPlgQDalr"
    "LfALyYiDqCaBKUmZUEE/ThuaUIeGckEYc4YILlGOg7WkAQEBhRo1CqbacJJXD333tQORPE2WM86K"
    "6doPc3fkmgFjHVOY6IVO2GXGGyfbMh+Ce6Pn9lyq7YUqBznKS/C/uMm7+70qtc7eundHL4t0in++"
    "OHprn5xy2nNAcs8Bf1ZSq/KgHWelZV77+IHpSWU1msNWn22l+M+DcLYyOAiXXXLYFVwvuxSZR6do"
    "4mj9B7k/Ovejk3JAFAEARJgAAAJ4fTxVQ2rD7g47iEMgtsIEleD+gNpkaggUwmYF2HAlu1wbfbis"
    "nY0+VDOGKUb4TUnEYYo+OOht9LF7AAClDkqhAKKhihIACpQSIACjk3AAFACFNZgAAAI="
)
_UDT_STRUCT_BLOB = base64.b64decode(
    "eH1mBSsThVbJasMwEP0V47uwVksqcSAJgfZUKCXXImuBQsGlSYs/vzOW7DjNoSfZWkaaN2/mzf+V"
    "0dwXxtuAbG8UqGqyBpXY4fsQ31z3gPI5TgyY6MY1SVSeWpLawt6XA+ykRnOhpLELD4qgdPXb/ul0"
    "fMjNSpN0HwAeRwSzjkitKemlE4T6PmqptODBlPKDrVIcL7yrM6QIc1maeEFHy6bZPbxpCPGjq08c"
    "CjbNXCkpNJ9lAhumgizoCEjaZfWTdQtdoeNemB1VB8Ts9QuKFIBc+W/gP3BEOqokSaYX8HgbifHe"
    "E0eZC94r2UYBhx7fzxj1Cm2nkCyTkXivJZxQnDgWArGJt4py2SbtagxGM9+0vaYz6svfyhyTT5EK"
    "STh3hkihPDHJWhKZZEm01ivB6lXBRydKCiJmGL9MwbFk10JhNeHzjEdyxtnpYUWdq/Mau2GN3QI0"
    "QnwP4VANk010shiDL/QNhsXXRazWtMxty2J0Z3eqPRzbeoVR3gJj9Zm9++lqrfNt89r1lmbquzbN"
    "9bZ55jZ1tr/VlwVco5NyQBQBADyYAAACeH08VUNqw+4OO4hDILbCBJXg/oDaZGoIFMJmBdhwJbsK"
    "G324rJ2NPlQzkAUONBt97FYDALHHMzEAoqGKDgADlA4gAKOTcAAUAIh2mAAAAg=="
)


def test_collector_takes_the_comments_of_a_udt_named_struct_from_the_udt():
    db, udt = 0x8A0E0026, 0x89FD0007
    objects = [ProgramObject(db, Ids.DB_CLASS_RID, "DB_StructUdt"), ProgramObject(udt, Ids.UDT_CLASS_RID, "Struct")]

    collector = _collect(objects, {db: _DB_STRUCT_UDT_BLOB, udt: _UDT_STRUCT_BLOB})

    # "Struct" is quoted, so it is the UDT, not an inline Struct
    assert dict(collector.resolve()) == {
        "DB_StructUdt.m": "m",
        "DB_StructUdt.a": "a",
        "DB_StructUdt.m.x": "x",
        "DB_StructUdt.a.x": "x",
    }


def test_collector_limits_how_many_comments_resolve(objects: list[ProgramObject], payloads: dict[int, bytes]):
    collector = _collect(objects, payloads)

    with pytest.raises(ValueError, match="more than 3 names"):
        collector.resolve(max_comments=3)


def test_comments_find_falls_back_to_the_array(objects: list[ProgramObject], payloads: dict[int, bytes]):
    comments = _collect(objects, payloads).resolve()

    assert comments.find("DB1.limits[1]") == "Limits"
    assert comments.find("DB1.limits") == "Limits"
    assert comments.find("DB1.cfg.gain") == "Gain"
    assert comments.find("DB1.limits[1].x") is None
    assert comments.find("DB1.cfg") is None
    assert comments.find("[0]") is None


def test_comments_find_falls_back_to_the_field_of_every_element():
    comments = Comments(
        {
            "DB1.motors": {"en-US": "Motors"},
            "DB1.motors.speed": {"en-US": "Motor speed"},
            "DB1.motors[2].speed": {"en-US": "Second motor speed"},
        }
    )

    assert comments.find("DB1.motors[1].speed") == "Motor speed"
    assert comments.find("DB1.motors[1,2].speed[3]") == "Motor speed"
    assert comments.find("DB1.motors[2].speed") == "Second motor speed"
    assert comments.find("DB1.motors[1].current") is None


def test_comments_find_falls_back_to_the_element_in_every_outer_element():
    comments = Comments(
        {
            "DB1.motors.speeds": {"en-US": "All speeds"},
            "DB1.motors.speeds[2]": {"en-US": "Second speed"},
            "DB1.motors[3].speeds": {"en-US": "Speeds of the third motor"},
        }
    )

    assert comments.find("DB1.motors[1].speeds[2]") == "Second speed"
    assert comments.find("DB1.motors[1].speeds[1]") == "All speeds"
    # The array the element is in wins over the same element in every outer element
    assert comments.find("DB1.motors[3].speeds[2]") == "Speeds of the third motor"


def test_comments_find_keeps_the_dimensions_of_an_index_together():
    comments = Comments({"DB.Grid": {"en-US": "Grid"}, "DB.Grid[10,1].x": {"en-US": "First x"}})

    assert comments.find("DB.Grid[11,3]") == "Grid"
    assert comments.find("DB.Grid[10,1].x") == "First x"
    assert comments.find("DB.Grid[10,2].x") is None  # never "DB.Grid[10].x" or the like


def test_comments_find_returns_quickly_for_a_name_with_many_indexes():
    # regression: find() tried every subset of the indexes, 2**60 names here
    comments = Comments({"DB" + ".y" * 60: {"en-US": "y"}})

    assert comments.find("DB" + ".y[0]" * 60) == "y"
    assert comments.find("DB" + ".z[0]" * 60) is None


@pytest.mark.parametrize(
    "name",
    [
        "DB.m[1].s[2]",
        "DB.m[2].s[1]",
        "DB.m[1].s[2].t[3]",
        "DB.m[1,2].s[3]",
        "DB.m.s",
        "DB.q[1]",
    ],
)
def test_comments_find_tries_the_names_in_the_order_of_every_subset_of_indexes(name: str):
    entries = {
        "DB.m.s": {"en-US": "m.s"},
        "DB.m.s[2]": {"en-US": "m.s[2]"},
        "DB.m[1].s": {"de-DE": "m[1].s"},
        "DB.m.s.t[3]": {"en-US": "m.s.t[3]"},
        "DB.m[1].s.t": {"en-US": "m[1].s.t"},
        "DB.a[2]": {"en-US": "a[2]"},
        "DB.a[1].b": {"en-US": "a[1].b"},
    }
    comments = Comments(entries)

    def every_subset(language: str | None) -> str | None:
        # the lookup find() replaced: every subset of the indexes, the fewest and the innermost first
        indexes = [matched.span() for matched in re.finditer(r"\[[^\]]*\]", name)]
        for count in range(len(indexes) + 1):
            for dropped in combinations(reversed(indexes), count):
                candidate = name
                for start, end in dropped:
                    candidate = candidate[:start] + candidate[end:]
                texts = entries.get(candidate, {})
                if (text := next(iter(texts.values()), None) if language is None else texts.get(language)) is not None:
                    return text
        return None

    for language in (None, "en-US", "de-DE"):
        assert comments.find(name, language) == every_subset(language)


def test_comments_find_falls_back_when_the_language_is_missing():
    comments = Comments({"DB1.values": {"de-DE": "Werte"}, "DB1.values[1]": {"en-US": "First value"}})

    assert comments.find("DB1.values[1]", language="de-DE") == "Werte"
    assert comments.find("DB1.values[1]") == "First value"


def test_comments_languages(objects: list[ProgramObject], payloads: dict[int, bytes]):
    comments = _collect(objects, payloads).resolve()

    assert comments["DB1.level"] == "Tank level"
    assert comments.find("DB1.level", language="de-DE") == "Füllstand"
    assert comments.find("DB1.level", language="fr-FR") is None
    assert comments.languages("DB1.level") == {"en-US": "Tank level", "de-DE": "Füllstand"}
    assert comments.languages("DB1.cfg") == {}


def test_comments_drop_names_without_text():
    comments = Comments({"DB1.a": {"en-US": "A"}, "DB1.b": {}})

    assert list(comments) == ["DB1.a"]
    assert len(comments) == 1
    with pytest.raises(KeyError):
        comments["DB1.b"]


@pytest.fixture()
def server(documents: dict[int, list[tuple[int, str]]], objects: list[ProgramObject]) -> Generator[Server, None, None]:
    srv = Server()
    for number in (1, 2, 3):
        srv.register_raw_db(number, bytearray(16))
    for obj in objects:
        if obj.class_id in (Ids.FB_CLASS_RID, Ids.UDT_CLASS_RID):
            srv.register_program_object(obj.rid, obj.class_id, obj.name)
    attributes = {
        INTERFACE: Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION,
        TAG_INTERFACE: Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION,
        LINE_COMMENTS: Ids.DATA_INTERFACE_LINE_COMMENTS,
        TAG_COMMENTS: Ids.DATA_INTERFACE_LINE_COMMENTS,
    }
    for rid, docs in documents.items():
        for dictionary, xml in docs:
            srv.add_explore_document(rid, attributes[dictionary], dictionary, xml)
    srv.start(port=0)
    yield srv
    srv.stop()


def test_get_comments(server: Server):
    with Client() as client:
        client.connect("127.0.0.1", port=server.port)
        connection = client._connection
        with patch.object(connection, "send_request", wraps=connection.send_request) as send_request:
            comments = client.get_comments()

    assert dict(comments) == {
        "DB1.level": "Tank level",
        "DB1.limits": "Limits",
        "DB1.cfg.gain": "Gain",
        "DB1.motor.speed": "Plant motor speed",
        "DB1.motor.current": "Motor current",
        "DB2.running": "Pump running",
        "DB3.speed": "Motor speed",
        "DB3.current": "Motor current",
        "IArea.Start": "Start button",
        "IArea.Drive.speed": "Motor speed",
        "IArea.Drive.current": "Motor current",
    }
    # one EXPLORE, of the program, asking for names and documents together
    assert [c.args for c in send_request.call_args_list if c.args[0] == FunctionCode.EXPLORE] == [
        (FunctionCode.EXPLORE, _build_explore_request(Ids.NATIVE_THE_PLC_PROGRAM_RID, list(CommentCollector.ATTRIBUTES)))
    ]


@pytest.mark.asyncio
async def test_async_get_comments(server: Server):
    async with AsyncClient() as client:
        await client.connect("127.0.0.1", port=server.port)
        connection = client._connection
        with patch.object(connection, "send_request", wraps=connection.send_request) as send_request:
            comments = await client.get_comments()

    assert dict(comments) == {
        "DB1.level": "Tank level",
        "DB1.limits": "Limits",
        "DB1.cfg.gain": "Gain",
        "DB1.motor.speed": "Plant motor speed",
        "DB1.motor.current": "Motor current",
        "DB2.running": "Pump running",
        "DB3.speed": "Motor speed",
        "DB3.current": "Motor current",
        "IArea.Start": "Start button",
        "IArea.Drive.speed": "Motor speed",
        "IArea.Drive.current": "Motor current",
    }
    # one EXPLORE, of the program, asking for names and documents together
    assert [c.args for c in send_request.call_args_list if c.args[0] == FunctionCode.EXPLORE] == [
        (FunctionCode.EXPLORE, _build_explore_request(Ids.NATIVE_THE_PLC_PROGRAM_RID, list(CommentCollector.ATTRIBUTES)))
    ]


def test_get_comments_raises_an_error_other_than_object_not_found(server: Server):
    with Client() as client:
        client.connect("127.0.0.1", port=server.port)
        # -63, as an S7-1500 V2.9 answers an EXPLORE of an object that lacks the requested relation
        refusal = S7ReturnValueError("EXPLORE failed", 0x80208100217BFFC1, b"")

        with patch.object(client, "explore", side_effect=refusal), pytest.raises(S7ReturnValueError) as raised:
            client.get_comments()

    assert raised.value.error_code == -63


@pytest.mark.asyncio
async def test_async_get_comments_raises_an_error_other_than_object_not_found(server: Server):
    async with AsyncClient() as client:
        await client.connect("127.0.0.1", port=server.port)
        refusal = S7ReturnValueError("EXPLORE failed", 0x80208100217BFFC1, b"")

        with patch.object(client, "explore", side_effect=refusal), pytest.raises(S7ReturnValueError) as raised:
            await client.get_comments()

    assert raised.value.error_code == -63


def test_get_comments_skips_a_block_with_a_corrupt_document(server: Server, caplog: pytest.LogCaptureFixture):
    server.add_explore_document(DB2, Ids.DATA_INTERFACE_LINE_COMMENTS, LINE_COMMENTS, "<InterfaceLineComments>")

    with Client() as client:
        client.connect("127.0.0.1", port=server.port)
        comments = client.get_comments()

    assert "DB2.running" not in comments
    assert comments["DB1.level"] == "Tank level"
    assert "Skipping the comments of object 0x8A0E0002" in caplog.text


@pytest.mark.asyncio
async def test_async_get_comments_skips_a_block_with_a_corrupt_document(server: Server, caplog: pytest.LogCaptureFixture):
    server.add_explore_document(DB2, Ids.DATA_INTERFACE_LINE_COMMENTS, LINE_COMMENTS, "<InterfaceLineComments>")

    async with AsyncClient() as client:
        await client.connect("127.0.0.1", port=server.port)
        comments = await client.get_comments()

    assert "DB2.running" not in comments
    assert comments["DB1.level"] == "Tank level"
    assert "Skipping the comments of object 0x8A0E0002" in caplog.text


def test_emulator_sends_the_line_comments_of_a_block_as_a_sparse_blob_array(server: Server):
    with Client() as client:
        client.connect("127.0.0.1", port=server.port)
        payload = client.explore(Ids.NATIVE_THE_PLC_PROGRAM_RID, CommentCollector.ATTRIBUTES)

    stream = compress_blob(DB3_LINE_COMMENTS, LINE_COMMENTS)
    # sparse array of BLOB: key 1, BlobRootId 0, the length and the stream, then the closing key 0
    attribute = bytes([0xA3]) + encode_uint32_vlq(Ids.DATA_INTERFACE_LINE_COMMENTS) + bytes([0x40, 0x14])
    assert attribute + bytes([0x01, 0x00]) + encode_uint32_vlq(len(stream)) + stream + b"\x00" in payload


@pytest.mark.parametrize(
    "rid",
    [
        Ids.NATIVE_THE_PLC_PROGRAM_RID,
        Ids.OBJECT_OMS_TYPE_INFO_CONTAINER,
        Ids.NATIVE_THE_CPU_EXEC_UNIT_RID,
        0x8A0E0005,
        0x12345678,
    ],
)
def test_emulator_rejects_documents_on_an_object_that_cannot_carry_them(rid: int):
    with pytest.raises(ValueError, match="not a registered data block or program object"):
        Server().add_explore_document(rid, Ids.DATA_INTERFACE_LINE_COMMENTS, LINE_COMMENTS, "<A/>")


def test_emulator_rejects_an_unknown_dictionary():
    with pytest.raises(ValueError, match="not a preset dictionary"):
        Server().add_explore_document(Ids.NATIVE_THE_I_AREA_RID, Ids.DATA_INTERFACE_LINE_COMMENTS, 0x12345678, "<A/>")
