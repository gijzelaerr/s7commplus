"""Tests for the block-interface parser.

The G2 fixtures are real EXPLORE blobs from a live S7-1200 G2 (FW V4.1) for an
optimized DB (``Data_block_1``) and a DB with a UDT member, exercising the
``DebugInfo_IntfDesc`` dict (Adler-32 ``0x66052b13``) and the RID -> SoftDataType
mapping. The instance-DB fixtures are real EXPLORE blobs from a live S7-1500
(FW V2.9) whose interface sits under a ``Values`` part: ``LGF_SinusCI_DB`` (an FB
instance), ``SLI_plcDB_rcvData_BRCV`` (a DB of a UDT) and ``IEC_Timer_S1_DB`` (an
instance of a library FB, which is referenced, not embedded).
"""

import base64
import zlib

import pytest

from s7commplus.block_interface import (
    BlockInterface,
    Member,
    block_interface_from_explore,
    parse_block_interface,
    resolve_id_path,
)

# Live S7-1200 G2 EXPLORE response for optimized DB "Data_block_1" (DB25), from
# the IdentES stream onward. Contains several preset-dict streams; the parser
# must skip IdentES (0x5814b03b) and target the interface dict (0x66052b13).
_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1YFLA7rZXBToQwEIZfxezdUCosECtmdRc9oAfhBRqZYJPSGrZoeHtni2ukS0+7lx6+djqdmX+m"
    "p4mgNhGbwehXK5Gj73/ECSejJKTrNCZhlJCUuP18WCvDu0/7xprcrY4mYZTF6xRtktVVHXo49fAb"
    "D488PPbwxMPTZR5cfkCdqfLCVfkbSOB7eNSDMnlMWDADbKu/ldS8eRZ7o/sRR9T9NbllgcuZ1XPJ"
    "VTvwFkr4ApnjP7VAWc37FkzBOyHHvMLpRMgTZcEMs11VDOrdYBBcCjNOphRvXNzA43Mn00nH8aZp"
    "xGRY4suxKvAgFO9Hm7IDeoEOYylBteYDmzz7LeGf/n8AgprvX6OhQEAVAKOTcAAUAIZ3mAAAAnh9"
    "ZgUrE42Y224bOQyGX8XwPWGROi+aAE1TYHvVxWLRW0NHINhsncZOEezTl5qjPVM3vUlGE/ET+YtD"
    "Snm7Mrp1YbzckNuLDrTZ9T1o2Lv7u77icbL3O4TISRhez/PD9K+m75kUz/77A881pEhrb9WUA0Mz"
    "udneffry8Y8W/T423/a4Szln8p5AIQpQpAyEEA1QwWKKTsmjHepPOyuV1xPdbHtNWWbVTj3cNPpX"
    "TjT5h9ldrohX320I+q4h9zoiEk/idlUeb7ZfiGu66NNp+MoGuvK20QfxSYmpnbUoedLdh/v3+n2T"
    "8p9nrl2s/Sa98GchijEhGw8YkwelLYE30oJ1yQWSJsla2ejPh2NLhg3DVZZaqhK5oVkHqlQCV50C"
    "4ZRxwjprq9m2PTqzyRyFpGLA6aJBZV/ABRVA+sCvtYjV0tLG5GBTVR4cEq/jLPKTRJDCCMxBoo+4"
    "tJEuVO+KBJfQgLIhQ6iSQyJHhLy2dnZpQ6FaVF6ArDlyPK6AjzlweNkEgw6VXsXD0aAK0UJIxPFE"
    "ChxPSWC1z84a61Gs1qmOs0xKDcJGVhprBC+UZc29taiVMxRXGkShCvISxiPbRG1Za68guFyCSCkI"
    "HZY2WlcKaAyw4xyP4um+mgop8/uSpE5FLm1SirypMUCKVYIKQYEzPPSBXIq2RGlrZ7Mbs+d2rtzt"
    "KLFswknYLJzP4J2roGQUEKRLQNJirlkgJ9f2rLe3xByqbfsUNI7V5lgey4ndLHtuHPvwcjoMlXUu"
    "X13if26Mvtr6ztNzGo20p5fH4/7YTpn88/C0Tw/p8ToQByCKFVHO/p2e2tFlX5/Lt/1/h+bqEqgn"
    "oBmJ7NF3TqMVV43cf5/2f326X5LcSJI0ktQVkp5ID78kGTWS9IphJkb+JcNPcZkVw46MdPh6vCLQ"
    "rDi5keSuxOVG3jN3w0P4nyt2eVN3NQbZiulPsX7E8lWs3Rf4ahrexJox5QiXwPanEfj12Dv5cGTo"
    "KVyVEe2oI8nOTbmi4qzmM18XTr9BJTFq2roe84Y7y+Z40S6+X3acqb10nWXdRbpjYTO4hqGWWDy6"
    "BPFNam5cnTeHzWEwnQduHqCneSDPno2an705s9bnA3GGIjoz6TJtGph++d0gzW13/e22jcVvNXL6"
    "R0wvkRjmt9LHv6ZSuOvuxu8WV7LbHxNPf/Kjk3JAFAEAEJgAAAJ4fTxVQ2oDAAAAAAEAo6E/QBUA"
    "o7sMQBQAo70tQBQAo70lQBQAo5NaAAEAo5NlQBQAoqKiAAAAAA=="
)

# Live S7-1200 G2 EXPLORE response for DB "Data_block_1" after adding a member of
# a user UDT ("elettrovalvola"), from the interface stream onward. The blob
# bundles the DB interface and the UDT's own definition; the UDT member is
# expanded into Member.fields.
_DB_UDT_INTERFACE_BLOB = base64.b64decode(
    "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"
    "AKOTZUAUAKKiogAAAAA="
)

# Live S7-1500 (FW V2.9) EXPLORE response for instance DB "LGF_SinusCI_DB" (DB7),
# filtered to attribute 2544, from the zlib header onward. Its first <Part> is
# Kind="Values"; the members come from the embedded LGF_SinusCI FB.
_SINUS_INSTANCE_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTpVhbT+M4FP4rVefZ1PdLtVTiujvS7FYaqnngBTmJMyCxUAFF/Pw9ji91kgaWmQdEEud8"
    "Oba/7zvH/dgZ9dgY+xuy6lWg2SLUoLh3oT6EPT+en379cbH89uflDRjN7vns68356cJSy4hsJWq0"
    "ZYgTLlHVcIs4VqziuDKKGphE55vH85shxKIyurZWtMgJWiGuGUaVahWS1rmaNFRaSueZwT69bF9l"
    "ot0Mw1dAmIFNEvRi30oqq/AoWw8X8PL3M1gIrrkwgiiR6Rrr3i/nnHD+gYUT0Th9k+feXujxPJAB"
    "Y0Pj0PG8+MKBZg1yxMQgghEmG6yWVC05PlJCCKzF9YGeLwZgg6jcELJkeknxkZGcMEavC5f/vwHr"
    "v6+2Xmvl+1QgLCGpDcGQzpKRI6WpYOR62At8BN6tQadq/GYYxlTRU9irziPO3T3k2Zz5feraqaAC"
    "QiiwfQM9RbhnmEPEY+PugbcU32AcvCFaZlxxblTuRvzO47fTS3wptOJBVt/cw08vLi+MzRNUIlDS"
    "rN6ByVGphHXcIVuZFnEBW6GbmqHWSGalxZVUBoL+unv20p45TzdJW8U4sqw1iLfUgjbqCtW4bh3V"
    "QhMDOQKlF+lLq71n+yZiWH6JsVI3IDEnLUiMGowMYxYppSxvnHSNovOiqvtJRJ/1S0uTzXx92O5e"
    "hsaOPYmadXex6MWxFLfevRwIJJOBfP/B9TiOTsaJFHflC0A9DGSTgTIFbty/22EYnwzTKQwE6tvl"
    "UaqiHxo709nru1zMxOs4N2TbKlR///4ehwqYAdz1Q/e4lEfCxAxW3VniwfsMTMfTLp9qQ144vu/Z"
    "BP8yuw6aaEeLVEgLF+1SZ5JK/yfovhwsy4ieRUqupNWGIasbh7h1QH1RSdS24JSs4ZXg+EsDXuEU"
    "qQeCPKGUkxPDkqmdu21Q5EigeTphL/scylyAgwZ0ervGxb4hF2dd7GrXSxDYtdeOmAM+qoQVmq1J"
    "IEYTkphAylSDg9Pd4ygnJhOU5AlKHoZSWV3bW+garm7v2unEjIxonEwkZhIa1Mb79ekA6SRrjlCd"
    "ElOjlHAC8d3bKJtsFISnyXmwQlCZ9wRnxWQ6rP54nD2GNV7Ea79I6dpPMV2TiBtuTBExVtAikWev"
    "jkV3DC+lEZxvqA0ek5QCiptSWBbS6EV8XhtU1oTZ2g60waS40Fhe/J42ZN6nV9/gTbKGyKwMvT98"
    "QJnzFGIj8yUJ1T09PT5N777JKjEj1BExZa5a4Mwvu+chbHZ1ihMxPUMGsGIEm4va865KZ4SrD75A"
    "M23JxHK8R+S8d4mXEpe8LBjbTSXfUP45xvZb+FBCh8ylMStCMNQuwb1eMnV7IZ+nLieWNND2HGi/"
    "QMnD9oueE2XIOfskg3nJiu+2+dDbaUkKPcFgUaJ2S+WGPN47dDZ7yiagR32CT7tX3kmvvMuyawhr"
    "NVylSIqCOdEPP02PPk3WT3c/7+CYlE58kSeEJKJgIzBjhJXlP7z8Kwzh3BFal5scf4r8zR/oAkrx"
    "Ax184sdsCwYQ6p48opoRHewgDMCEbrsm9rXrl3AxxIqh8jkvntPiuSih5BfcR5Pl6FE5og98XJH3"
    "wFTImqZRLXujrB8Lo6QYlSPMuG4HKLPYd4rTT/qbsPoPObOuu6IAAAAA"
)

# Live S7-1500 (FW V2.9) EXPLORE response for DB "SLI_plcDB_rcvData_BRCV", declared
# of the UDT "BRCV_User", filtered to attribute 2544, from the zlib header onward.
# Its first <Part> is Kind="Values"; the members come from the embedded DataTypeSource.
_UDT_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTnVfbahsxEP0V43dldRndTOwHOy0JpASSkIe+LHvRloJbByctoV/fGWm19npzKQVjS0I6"
    "Gs3MOTP+WBndVBjHAVmNKtCsSDWoj12qDynmy/n66uHT4u76qnzcNhfrct/8JvvL9e3moeg86FYI"
    "x7RxLQOoA6t0i1+4zJ0S0FUdPibq53JeRig6WKLi7wtplHGhtUxLBwxakKySTWBKiVDZ1lRCwHzI"
    "YzJyELFjc8kcSod0DTI0pZVH4lQvxzltXFwaNEjifHO7QQ9qbbUVoNyQt30B/E+jk2JSdxdenuVy"
    "nrKAMoP6NCxzacnFtX43ejpf8krbhtZyKZng+LkXesHVQrkzLZX1Br6+0v19dGBQoX89cPPl7pHc"
    "PNqvGTdxP18AX0g481qC9HH/qC34CD26IBKcv3gR/bLBaEW5uAhbNLTdbFJQd23YYpJKXpLvYlVN"
    "+th7Gbwlf/S0kcCpYelrglRyaEso8njZZwP6AkTi13X4+Y1YRgy532NJQkrNml+odmCVbmQlGA/4"
    "avBdxSrrLGuc4XVX18Abg4cuvz8Rx2d4FyABlFItE513DDqvmfONZl1Xt6q23CiNtxajM0YLMAEC"
    "47WpGcjGsIqDYSpgzuHI152PZ4ps3eog+NSBnNZu3dayc6FhQemKgeXAXFtz1qHt0DbcG2PmRy0B"
    "PbwXaQqGhixSkVVhX4pehwex09HZN3Q0aTPlfzFG0RMU/iYMdnU9jp7gmIxDzeT+FGKdISjICcJM"
    "IGyGuEU93v04xXAZw0DGsBMMlzEuA8pQuQ7V8ymOyDh+eI6b4PiMgz1cKMXlnzetEWJ4kj+FMXwE"
    "o9+DgfwqyScwYmwNfw/H5ldJMcGRY3Pew5E0TDgy4vTd/+xpRN/diL4D2yPRT2m8Ot/NduSmBBgn"
    "8Zo84YehOt4j4TAxR2NvDmMhj4CESVBFbzSOiIH4MzCyiP/szotD3cor4+K8+g=="
)

# Live S7-1500 (FW V2.9) EXPLORE response for instance DB "IEC_Timer_S1_DB",
# filtered to attribute 2544, from the zlib header onward. Its Values part holds
# only a reference to the library FB IEC_TIMER, not its source.
_LIBRARY_INSTANCE_DB_INTERFACE_BLOB = base64.b64decode(
    "eH1mBSsTjZWxDoMgEIZfpWG/IoLnYcTB1sGhS5t0JQL6AH3/oShGYzu0K8PdR374v9/NSN/FeAyk"
    "ORjoxJOD1uySH1LmhrX9s6v67mLnAn/Zh7DXlsthLFShFfhAOSgSCBGVYJwylDhpP+Qq3mIpTsPs"
    "PqO/dXceic/EHVIQZUCQk/egFBKQoAGcxECq1Dpzjm3PeGbcOizRxn+zesqwf4btBNVCsBabYds5"
    "m7fwfQ1fzFx/CKF5"
)

# Live S7-1500 (FW V2.9) EXPLORE response for DB "Nested_DB_Three_Levels", filtered
# to attributes 2544 and 2546, from the zlib header onward. Its inline Structs nest
# three levels deep; each one's members sit in a Kind="Structure" part whose
# ParentId is the member's ID path (e.g. "52:52:52" for Branch1.Branch11.Branch111).
# It also holds an Array of Struct, a UDT inside a Struct and a member name full of
# special characters, and its member IDs do not follow declaration order.
_NESTED_STRUCT_DB_INTERFACE_BLOB = base64.b64decode(
    "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"
)


_ARRAY_OF_UDT = (
    '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
    '<Member Name="arr" Type=\'Array[0..1] of "Motor"\' RID="0x02010011" ID="60" LID="1" StdO="0" />'
    "</Root></Payload></Part></BlockInterface>"
)


def test_parse_block_interface_types():
    # <Member> types are RID references into the SoftDataType table; a RID
    # outside the 0x0200_00XX namespace is a complex type left as raw hex.
    xml = (
        "<BlockInterface><Part><Payload><Root>"
        '<Member ID="51" Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        '<Member ID="53" Name="speed" RID="0x02000005" StdO="16" LID="12" />'
        '<Member ID="54" Name="gain" RID="0x02000008" StdO="32" LID="14" />'
        '<Member ID="60" Name="timer" RID="0x0300abcd" StdO="48" LID="20" />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("flag", "Bool", 9, 0, 0x02000001, id=51),
        Member("speed", "Int", 12, 16, 0x02000005, id=53),
        Member("gain", "Real", 14, 32, 0x02000008, id=54),
        Member("timer", "0x0300ABCD", 20, 48, 0x0300ABCD, id=60),
    ]


def test_parse_block_interface_member_without_id_defaults_to_zero():
    xml = (
        "<BlockInterface><Part><Payload><Root>"
        '<Member Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [Member("flag", "Bool", 9, 0, 0x02000001, id=0)]


def test_parse_block_interface_fb_sections():
    # FB/OB interfaces are organized in sections; the section-header <Member>s
    # (Input/Static, no RID) must be skipped, real members tagged with their
    # section. Complex members carry a ready-made ``Type`` attribute (arrays),
    # scalar ones resolve from the RID.
    xml = (
        '<BlockInterface><Part Kind="BlockSource"><Payload><Root>'
        '<Member ID="2" Name="Input" SubPartIndex="0" StdO="0" />'
        '<Member ID="5" Name="Static" SubPartIndex="3" StdO="0" />'
        "</Root></Payload>"
        "<SubParts>"
        '<Part Kind="InputSection"><Payload><Member>'
        '<Member ID="51" Name="puls_start_stop" RID="0x02000001" StdO="0" LID="9" />'
        "</Member></Payload></Part>"
        '<Part Kind="StaticSection"><Payload><Member>'
        '<Member ID="61" Name="num_step" RID="0x02000005" StdO="0" LID="19" />'
        '<Member ID="62" Name="timers" RID="0x0201001F"'
        ' Type="Array[0..5] of IEC_TIMER" StdO="16" LID="20" />'
        '<Member ID="63" Name="echo" RID="0x02010001"'
        ' Type="Array[0..2] of Bool" StdO="784" LID="21" />'
        "</Member></Payload></Part>"
        "</SubParts></Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("puls_start_stop", "Bool", 9, 0, 0x02000001, "Input", id=51),
        Member("num_step", "Int", 19, 0, 0x02000005, "Static", id=61),
        Member("timers", "Array[0..5] of IEC_TIMER", 20, 16, 0x0201001F, "Static", id=62),
        Member("echo", "Array[0..2] of Bool", 21, 784, 0x02010001, "Static", id=63),
    ]


def test_parse_block_interface_udt_member_expands_fields():
    # A UDT member carries a readable ``Type`` ("MyUdt", TIA quotes), a RID in
    # the UDT object namespace (0x91......) and a ``SubPartIndex`` pointing at the
    # UDT's definition embedded under <SubParts>. That definition is expanded
    # into Member.fields, not surfaced as top-level members.
    xml = (
        '<BlockInterface><Part Kind="DBSource"><Payload><Root>'
        '<Member ID="51" Name="flag" RID="0x02000001" StdO="0" LID="9" />'
        '<Member ID="52" Name="valve" RID="0x91000001" Type="&quot;MyUdt&quot;"'
        ' SubPartIndex="0" StdO="16" LID="10" />'
        "</Root></Payload>"
        '<SubParts><Part Kind="DataTypeSource"><Payload><Root>'
        '<Member ID="60" Name="open_cmd" RID="0x02000001" StdO="0" LID="1" />'
        '<Member ID="61" Name="level" RID="0x02000005" StdO="16" LID="2" />'
        "</Root></Payload></Part></SubParts>"
        "</Part></BlockInterface>"
    )
    assert parse_block_interface(xml) == [
        Member("flag", "Bool", 9, 0, 0x02000001, "", id=51),
        Member(
            "valve",
            '"MyUdt"',
            10,
            16,
            0x91000001,
            "",
            fields=[
                Member("open_cmd", "Bool", 1, 0, 0x02000001, "", id=60),
                Member("level", "Int", 2, 16, 0x02000005, "", id=61),
            ],
            id=52,
        ),
    ]


def test_block_interface_from_live_g2_db_with_udt():
    members = block_interface_from_explore(_DB_UDT_INTERFACE_BLOB)
    # 12 top-level members; the embedded UDT definition is not surfaced flat.
    assert len(members) == 12
    valve = members[-1]
    assert (valve.name, valve.data_type, valve.rid) == (
        "elettrovalvola_1",
        '"elettrovalvola"',
        0x91000001,
    )
    assert [(f.name, f.data_type) for f in valve.fields] == [
        ("fc_apertura", "Bool"),
        ("fc_chiusura", "Bool"),
        ("stato_ev", "Int"),
        ("allarme_ev", "Int"),
        ("cons_ev", "Bool"),
        ("perc_apertura", "Real"),
    ]


def test_block_interface_from_live_g2_db():
    members = block_interface_from_explore(_DB_INTERFACE_BLOB)
    got = [(m.name, m.data_type) for m in members]
    assert got == [
        ("selettore_man_auto", "Bool"),
        ("puls_start_stop_ciclo", "Bool"),
        ("setpoint_freq_motore", "Int"),
        ("kp_PID", "Real"),
        ("ki_PID", "Real"),
        ("kd_PID", "Real"),
        ("cons_motore", "Bool"),
        ("retroazione_motore", "Int"),
        ("temperatura_motore", "Int"),
        ("tensione_misurata", "Real"),
        ("corrente_misurata", "Real"),
    ]


def test_block_interface_from_live_s7_1500_instance_db():
    members = block_interface_from_explore(_SINUS_INSTANCE_DB_INTERFACE_BLOB)
    assert [(m.name, m.section, m.lid) for m in members] == [
        ("amplitude", "Input", 14),
        ("offset", "Input", 15),
        ("periode", "Input", 16),
        ("phaseShift", "Input", 41),
        ("callOB", "Input", 17),
        ("reset", "Input", 28),
        ("value", "Output", 18),
        ("error", "Output", 19),
        ("status", "Output", 32),
        ("subFunctionStatus", "Output", 21),
        ("statRad", "Static", 22),
        ("statCounter", "Static", 23),
    ]


def test_block_interface_from_live_s7_1500_udt_db():
    members = block_interface_from_explore(_UDT_DB_INTERFACE_BLOB)
    assert [(m.name, m.data_type, m.lid) for m in members] == [
        ("Counter_1", "Int", 14),
        ("Counter_10", "Int", 15),
        ("Timer", "Time", 16),
        ("Random", "Real", 17),
        ("Heart_Beat", "Bool", 18),
        ("Sine_1Hz", "Real", 19),
        ("Sine_5Hz", "Real", 20),
        ("Sine_10Hz", "Real", 21),
        ("Sine_50Hz", "Real", 22),
    ]


def test_block_interface_from_live_s7_1500_library_instance_db_is_empty():
    # The Values part only references the library FB, so there is no source to parse.
    assert block_interface_from_explore(_LIBRARY_INSTANCE_DB_INTERFACE_BLOB) == []


def test_parse_block_interface_values_part_without_source_is_empty():
    assert parse_block_interface('<BlockInterface><Part Kind="Values"><Payload /></Part></BlockInterface>') == []
    assert parse_block_interface('<BlockInterface><Part Kind="Values"><Payload /><SubParts /></Part></BlockInterface>') == []


def test_parse_block_interface_rejects_deep_nesting():
    # A 400-part chain with one member per part used to exceed Python's recursion limit
    member = '<Member ID="1" LID="1" Name="m" RID="0x02000011" SubPartIndex="{0}"/>'
    parts = "".join(
        f'<Part Kind="Structure"><Payload><Member>{member.format(i + 1)}</Member></Payload></Part>' for i in range(400)
    )
    xml_text = (
        f'<BlockInterface><Part Kind="DBSource"><Payload><Root>{member.format(0)}</Root></Payload>'
        f"<SubParts>{parts}</SubParts></Part></BlockInterface>"
    )

    with pytest.raises(ValueError, match="nests deeper"):
        parse_block_interface(xml_text)


# k Structure parts, each with two members pointing at the next part, expand to 2**k - 1 members.
# 20 parts is the reviewer's reproducer (about a million members); 3 parts expand to exactly 7.
@pytest.mark.parametrize(
    ("k", "max_members", "rejected"),
    [(20, 100_000, True), (3, 7, False), (3, 6, True)],
)
def test_parse_block_interface_caps_exponential_expansion(k, max_members, rejected):
    parts = []
    for i in range(k):
        mem = (
            ""
            if i == k - 1
            else (
                f'<Member ID="1" LID="1" Name="a" RID="0x02000011" SubPartIndex="{i + 1}"/>'
                f'<Member ID="2" LID="2" Name="b" RID="0x02000011" SubPartIndex="{i + 1}"/>'
            )
        )
        parts.append(f'<Part Kind="Structure"><Payload><Member>{mem}</Member></Payload></Part>')
    top = '<Member ID="1" LID="1" Name="s" RID="0x02000011" SubPartIndex="0"/>'
    xml_text = (
        f'<BlockInterface><Part Kind="DBSource"><Payload><Root>{top}</Root></Payload>'
        f"<SubParts>{''.join(parts)}</SubParts></Part></BlockInterface>"
    )

    if rejected:
        with pytest.raises(ValueError, match="more than"):
            parse_block_interface(xml_text, max_members=max_members)
    else:
        parse_block_interface(xml_text, max_members=max_members)


def test_block_interface_from_live_s7_1500_nested_struct_db():
    # An inline Struct member points via `SubPartIndex` at a Kind="Structure" part
    # in the same <SubParts> list as its parent, also when the parent is itself a
    # Structure part.
    def leaf(name: str, offset: int = 0) -> Member:
        return Member(name, "Bool", 9, offset, 0x02000001, id=51)

    def branch(name: str, lid: int, offset: int, rid: int, member_id: int, fields: list[Member]) -> Member:
        return Member(name, "Struct", lid, offset, rid, fields=fields, id=member_id)

    assert block_interface_from_explore(_NESTED_STRUCT_DB_INTERFACE_BLOB) == [
        Member(
            "Array of struct",
            "Array[0..1] of Struct",
            20,
            0,
            0x9A080000,
            fields=[Member("Array of bool", "Array[0..1] of Bool", 16, 0, 0x02010001, id=51)],
            id=58,
        ),
        branch(
            "Special struct",
            22,
            32,
            0x92090000,
            59,
            [
                Member(
                    "UDT",
                    '"BRCV_User"',
                    14,
                    0,
                    0x9100000C,
                    fields=[
                        Member("Counter_1", "Int", 14, 0, 0x02000005, id=54),
                        Member("Counter_10", "Int", 15, 16, 0x02000005, id=55),
                        Member("Timer", "Time", 16, 32, 0x0200000B, id=56),
                        Member("Random", "Real", 17, 64, 0x02000008, id=57),
                        Member("Heart_Beat", "Bool", 18, 96, 0x02000001, id=58),
                        Member("Sine_1Hz", "Real", 19, 112, 0x02000008, id=59),
                        Member("Sine_5Hz", "Real", 20, 144, 0x02000008, id=60),
                        Member("Sine_10Hz", "Real", 21, 176, 0x02000008, id=61),
                        Member("Sine_50Hz", "Real", 22, 208, 0x02000008, id=62),
                    ],
                    id=51,
                ),
                # The PLC stores this name already mojibake'd (UTF-8 "¬ß" for "§" etc.); it is asserted as sent.
                Member("Special_!¬ß$%&/()=?`¬¥\\+~*'#_-:.,<>|@^¬∞‚Ç¨¬µ{[]}", "SoftType#149", 18, 240, 0x02000095, id=52),
            ],
        ),
        leaf("Leaf1", 288),
        branch(
            "Branch1",
            11,
            304,
            0x92010000,
            52,
            [
                leaf("Leaf11"),
                branch(
                    "Branch11",
                    11,
                    16,
                    0x92040000,
                    52,
                    [leaf("Leaf111"), branch("Branch111", 11, 16, 0x92070000, 52, [leaf("Leaf1111")])],
                ),
                branch("Branch12", 12, 48, 0x92050000, 53, [leaf("Leaf121")]),
            ],
        ),
        branch(
            "Branch2",
            12,
            368,
            0x92020000,
            53,
            [
                leaf("Leaf21"),
                branch("Branch21", 11, 16, 0x92030000, 52, [leaf("Leaf211")]),
                branch("Branch22", 12, 32, 0x92060000, 53, [leaf("Leaf221")]),
            ],
        ),
    ]


def test_array_of_udt_member_names_its_udt():
    # the quoted element type of an array member is its element_type and a reference
    info = BlockInterface.from_xml(_ARRAY_OF_UDT)
    assert info.members[0].element_type == "Motor"
    assert info.references == {"Motor"}


# an 11-digit id exceeds the \d{1,10} segment pattern; an index list holds integers only
@pytest.mark.parametrize(
    "id_path", ["", "60:", "x", "60[0", "99", "60:99", "60:12345678901", "60[]", "60[x,y]", "60[0,]", "60[0]]"]
)
def test_resolve_id_path_rejects_malformed_or_unknown(id_path: str):
    assert resolve_id_path(BlockInterface.from_xml(_ARRAY_OF_UDT).members, id_path) is None


def test_resolve_id_path_stops_at_a_type_that_is_not_embedded():
    # arr is typed with "Motor", but the interface carries no definition of it
    assert resolve_id_path(BlockInterface.from_xml(_ARRAY_OF_UDT).members, "60[0]:51") is None


def test_resolve_id_path_does_not_look_up_an_empty_struct_in_types():
    # an inline Struct is always embedded, so "Struct" in types must not supply its fields
    xml = (
        '<BlockInterface><Part Kind="DBSource"><Payload><Root>'
        '<Member ID="60" Name="s" RID="0x00000000" SubPartIndex="0" />'
        '</Root></Payload><SubParts><Part Kind="Structure"><Payload /></Part></SubParts></Part></BlockInterface>'
    )
    members = BlockInterface.from_xml(xml).members
    assert members[0].data_type == "Struct"
    assert resolve_id_path(members, "60:51", types={"Struct": [Member("wrong", "Int", 0, 0, 0, id=51)]}) is None


def test_instance_db_names_its_fb():
    # Live S7-1500 LGF_SinusCI_DB: the FB sits below the Values part
    assert BlockInterface.from_explore(_SINUS_INSTANCE_DB_INTERFACE_BLOB).source == "LGF_SinusCI"


def test_udt_db_has_no_source():
    # A DataTypeSource below Values is a DB of a UDT, not an instance
    assert BlockInterface.from_explore(_UDT_DB_INTERFACE_BLOB).source is None


def test_info_from_explore_without_stream_is_empty():
    assert BlockInterface.from_explore(b"no zlib stream here") == BlockInterface([], None, frozenset())


def test_from_xml_rejects_malformed_xml():
    # ElementTree's ParseError must not leak out of the public API
    with pytest.raises(ValueError, match="not well-formed"):
        BlockInterface.from_xml("not xml")


def test_from_xml_without_part_is_empty():
    assert BlockInterface.from_xml("<Other />") == BlockInterface([], None, frozenset())


def test_from_xml_values_part_with_empty_block_has_no_source():
    # an empty Block attribute must not become the source name ""
    xml = '<BlockInterface><Part Kind="Values"><SubParts><Part Kind="BlockSource" Block="" /></SubParts></Part></BlockInterface>'
    assert BlockInterface.from_xml(xml).source is None


def test_from_xml_references_skip_empty_names():
    xml = (
        '<BlockInterface><Part Kind="DBSource" Block=""><Payload><Root>'
        '<Member Name="a" RID="0x02010001" Type=\'Array[0..1] of "Motor"\' />'
        '</Root></Payload></Part><ExternalType /><ExternalType Name="Ext" /></BlockInterface>'
    )
    assert BlockInterface.from_xml(xml).references == {"Motor", "Ext"}


def test_from_explore_raises_on_corrupt_stream():
    # a DebugInfo IntfDesc header followed by an invalid deflate block,
    # which find_preset_stream selects and decompress_blob rejects
    payload = bytes.fromhex("787d 66052b13") + b"\xff" * 8
    with pytest.raises(ValueError, match="corrupt") as caught:
        BlockInterface.from_explore(payload)
    assert isinstance(caught.value.__cause__, zlib.error)


def test_from_xml_references_skip_array_bound_constants():
    xml = (
        '<BlockInterface><Part Kind="DBSource" Block="DB1"><Payload><Root>'
        '<Member Name="a" RID="0x02010011" Type=\'Array[1.."c_max"] of "Motor"\' />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert BlockInterface.from_xml(xml).references == {"Motor"}


def test_from_xml_references_leave_out_the_block_itself():
    # Synthetic: the captured DBs leave Block off their primary Part, but a UDT or FB explored on its own
    # may name itself there. Only the UDT its member is typed with is a reference.
    xml = (
        '<BlockInterface><Part Kind="DataTypeSource" Block="Motor"><Payload><Root>'
        '<Member ID="51" Name="valve" RID="0x02000005" Type=\'"Valve"\' />'
        "</Root></Payload></Part></BlockInterface>"
    )
    assert BlockInterface.from_xml(xml).references == {"Valve"}


@pytest.mark.parametrize(
    ("data_type", "expected"),
    [
        ("Int", "Int"),
        ("IEC_TIMER", "IEC_TIMER"),
        ('"Motor"', "Motor"),
        ("Array[0..5] of IEC_TIMER", "IEC_TIMER"),
        ('Array[1.."c_max"] of "Motor"', "Motor"),
        ('Array[0.."N"] of Bool', "Bool"),
    ],
)
def test_member_element_type(data_type: str, expected: str):
    # a UDT, a library type and an elementary type are all named
    assert Member("m", data_type, 0, 0, 0).element_type == expected


def test_resolve_id_path_follows_types_into_array_element_udt():
    members = BlockInterface.from_xml(_ARRAY_OF_UDT).members
    motor = [Member("speed", "Int", 1, 0, 0x02000005, id=51)]
    assert resolve_id_path(members, "60[0]:51", types={"Motor": motor}) == "arr[0].speed"


def test_resolve_id_path_follows_types_into_library_type():
    # IEC_TIMER is a library type, quoted nowhere, and is still found by its element_type
    timer = Member("t", "Array[0..5] of IEC_TIMER", 1, 0, 0x02010011, id=7)
    pt = [Member("PT", "Time", 1, 0, 0x0200000B, id=3)]
    assert resolve_id_path([timer], "7[2]:3", types={"IEC_TIMER": pt}) == "t[2].PT"
