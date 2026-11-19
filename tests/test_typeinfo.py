"""Tests for the S7CommPlus type-info parser (PVartypeList / POffsetInfoType / VarnameList).

Pins the on-wire layouts and the tree-building behaviour browse() relies on to
reconstruct the per-tag symbol tree from a PLC's EXPLORE type-info response.
"""

import importlib.util
import struct
from pathlib import Path

from s7commplus import typeinfo as ti
from s7commplus.protocol import DataType
from s7commplus.vlq import encode_uint32_vlq

_ALLTYPES_STD = Path(__file__).parent / "fixtures" / "s7_1500_db_alltypes_std.py"
_alltypes_std_spec = importlib.util.spec_from_file_location("s7_1500_db_alltypes_std", _ALLTYPES_STD)
assert _alltypes_std_spec is not None and _alltypes_std_spec.loader is not None
alltypes_std = importlib.util.module_from_spec(_alltypes_std_spec)
_alltypes_std_spec.loader.exec_module(alltypes_std)


def _vartype_list_bytes(*elements: bytes) -> bytes:
    block = b"".join(elements)
    return struct.pack(">H", len(block) + 4) + struct.pack("<I", 1) + block + struct.pack(">H", 0)


def _multiblock_vartype_list_bytes(*blocks: tuple[bytes, ...]) -> bytes:
    """Frame several blocks of elements as a real multi-block PVartypeList.

    The first block carries the leading LE-u32 FirstId (counted in its length);
    subsequent blocks carry only elements. A BE-u16 zero block terminates the list.
    """
    out = b""
    for idx, elements in enumerate(blocks):
        block = b"".join(elements)
        if idx == 0:
            # FirstId is counted inside the first block's length.
            out += struct.pack(">H", len(block) + 4) + struct.pack("<I", 1) + block
        else:
            out += struct.pack(">H", len(block)) + block
    out += struct.pack(">H", 0)  # zero-length terminator block
    return out


def _varname_list_bytes(*names: str) -> bytes:
    block = b"".join(bytes([len(n.encode())]) + n.encode() + b"\x00" for n in names)
    return struct.pack(">H", len(block)) + block + struct.pack(">H", 0)


class TestSoftdatatype:
    def test_known_values(self) -> None:
        assert ti.Softdatatype.BOOL == 1
        assert ti.Softdatatype.BYTE == 2
        assert ti.Softdatatype.INT == 5
        assert ti.Softdatatype.REAL == 8
        assert ti.Softdatatype.LREAL == 48
        assert ti.Softdatatype.BBOOL == 40
        assert ti.Softdatatype.WSTRING == 62
        assert ti.Softdatatype.DTL == 67

    def test_supported_includes_scalars(self) -> None:
        for sdt in (ti.Softdatatype.BOOL, ti.Softdatatype.INT, ti.Softdatatype.REAL, ti.Softdatatype.LREAL):
            assert ti.is_softdatatype_supported(int(sdt))

    def test_supported_excludes_containers(self) -> None:
        # VOID(0), ARRAY(16), STRUCT(17), VARIANT(63) are container/marker types, not leaves.
        for sdt in (0, 16, 17, 63):
            assert not ti.is_softdatatype_supported(sdt)


class TestDatatypeSize:
    def test_one_byte_types(self) -> None:
        for sdt in (
            ti.Softdatatype.BOOL,
            ti.Softdatatype.BYTE,
            ti.Softdatatype.CHAR,
            ti.Softdatatype.USINT,
            ti.Softdatatype.SINT,
            ti.Softdatatype.BBOOL,
        ):
            assert ti.datatype_size(int(sdt)) == 1

    def test_two_byte_types(self) -> None:
        for sdt in (ti.Softdatatype.WORD, ti.Softdatatype.INT, ti.Softdatatype.UINT, ti.Softdatatype.DATE):
            assert ti.datatype_size(int(sdt)) == 2

    def test_four_byte_types(self) -> None:
        for sdt in (ti.Softdatatype.DWORD, ti.Softdatatype.DINT, ti.Softdatatype.REAL, ti.Softdatatype.UDINT):
            assert ti.datatype_size(int(sdt)) == 4

    def test_eight_byte_types(self) -> None:
        for sdt in (ti.Softdatatype.LREAL, ti.Softdatatype.LINT, ti.Softdatatype.LWORD, ti.Softdatatype.ULINT):
            assert ti.datatype_size(int(sdt)) == 8

    def test_dtl_is_twelve(self) -> None:
        assert ti.datatype_size(int(ti.Softdatatype.DTL)) == 12

    def test_string_uses_unspecified_length(self) -> None:
        # STRING/WSTRING stride comes from the array offset-info's first unspecified field + 2.
        assert ti.datatype_size(int(ti.Softdatatype.STRING), string_len=10) == 12

    def test_unknown_is_zero(self) -> None:
        assert ti.datatype_size(0) == 0


def _name_entry(s: str) -> bytes:
    raw = s.encode("utf-8")
    return bytes([len(raw)]) + raw + b"\x00"  # 1-byte len + UTF-8 bytes + null terminator


class TestVarnameList:
    def test_single_block_two_names(self) -> None:
        block = _name_entry("Foo") + _name_entry("Ab")  # 5 + 4 = 9 bytes
        data = struct.pack(">H", len(block)) + block + struct.pack(">H", 0)  # block + zero terminator
        names, off = ti.parse_varname_list(data, 0)
        assert names == ["Foo", "Ab"]
        assert off == len(data)

    def test_empty_list(self) -> None:
        data = struct.pack(">H", 0)  # immediate zero blocklen
        names, off = ti.parse_varname_list(data, 0)
        assert names == []
        assert off == 2

    def test_with_offset(self) -> None:
        block = _name_entry("X")
        data = b"\xff\xff" + struct.pack(">H", len(block)) + block + struct.pack(">H", 0)
        names, off = ti.parse_varname_list(data, 2)
        assert names == ["X"]
        assert off == len(data)


class TestOffsetInfo:
    def test_std_new_code8_opt_then_nonopt(self) -> None:
        # New Std (8): first u16 = optimized, second = non-optimized.
        data = struct.pack("<HH", 4, 20)
        oi, off = ti.parse_offset_info(data, 0, 8)
        assert oi.opt_addr == 4
        assert oi.nonopt_addr == 20
        assert not oi.has_relation and not oi.is_1dim and not oi.is_mdim
        assert off == 4

    def test_std_legacy_code1_nonopt_then_opt(self) -> None:
        # Legacy StructElemStd (1): order swapped — first u16 = non-optimized.
        data = struct.pack("<HH", 20, 4)
        oi, off = ti.parse_offset_info(data, 0, 1)
        assert oi.nonopt_addr == 20
        assert oi.opt_addr == 4

    def test_string_unspecified_and_addresses(self) -> None:
        # String (9): u16 unspec1, u16 unspec2, u32 opt, u32 nonopt.
        data = struct.pack("<HHII", 254, 256, 8, 100)
        oi, off = ti.parse_offset_info(data, 0, 9)
        assert oi.unspecified1 == 254
        assert oi.opt_addr == 8 and oi.nonopt_addr == 100
        assert off == 12

    def test_array1dim(self) -> None:
        # Array1Dim (10): u16,u16,u32 opt,u32 nonopt,i32 lower,u32 count.
        data = struct.pack("<HHIIiI", 0, 0, 16, 50, -3, 10)
        oi, off = ti.parse_offset_info(data, 0, 10)
        assert oi.is_1dim and not oi.has_relation
        assert oi.array_lower_bound == -3
        assert oi.array_element_count == 10
        assert oi.opt_addr == 16 and oi.nonopt_addr == 50
        assert off == 20

    def test_struct_has_relation(self) -> None:
        # Struct (12): u16,u16,u32 opt,u32 nonopt,u32 relid, then 4x u32 structinfo.
        data = struct.pack("<HHIII" + "I" * 4, 0, 0, 0, 0, 0x1234, 0, 0, 0, 0)
        oi, off = ti.parse_offset_info(data, 0, 12)
        assert oi.has_relation
        assert oi.relation_id == 0x1234
        assert off == len(data)

    def test_struct1dim_has_relation_and_array(self) -> None:
        # Struct1Dim (13): u16,u16,u32,u32,i32 lower,u32 count,u32 nonoptsize,u32 optsize,u32 relid,4xu32.
        data = struct.pack("<HHIIiIIII" + "I" * 4, 0, 0, 0, 0, 0, 5, 24, 16, 0x55, 0, 0, 0, 0)
        oi, off = ti.parse_offset_info(data, 0, 13)
        assert oi.has_relation and oi.is_1dim
        assert oi.array_element_count == 5
        assert oi.relation_id == 0x55

    def test_arraymdim_consumes_and_flags(self) -> None:
        # ArrayMDim (11): base 20 + 6 i32 lower bounds + 6 u32 counts = 68 bytes.
        data = (
            struct.pack("<HHIIiI", 0, 0, 0, 0, 0, 12)
            + struct.pack("<6i", 0, 0, 0, 0, 0, 0)
            + struct.pack("<6I", 3, 4, 0, 0, 0, 0)
        )
        oi, off = ti.parse_offset_info(data, 0, 11)
        assert oi.is_mdim and not oi.has_relation
        assert oi.mdim_element_count[:2] == [3, 4]
        assert off == 68

    def test_structmdim_consumes_and_flags(self) -> None:
        # StructMDim (14): 68 (mdim) + nonoptsize,optsize,relid + 4x structinfo = 96 bytes.
        data = (
            struct.pack("<HHIIiI", 0, 0, 0, 0, 0, 1)
            + struct.pack("<6i", *([0] * 6))
            + struct.pack("<6I", *([1] + [0] * 5))
            + struct.pack("<III" + "I" * 4, 8, 8, 0x77, 0, 0, 0, 0)
        )
        oi, off = ti.parse_offset_info(data, 0, 14)
        assert oi.has_relation and oi.is_mdim
        assert oi.relation_id == 0x77
        assert off == 96

    def test_fbsfb_has_relation(self) -> None:
        # FbSfb (15): u16,u16,u32,u32,u32 relid,4x info,u32 retainoff,u32 volatileoff = 40 bytes.
        data = struct.pack("<HHIII" + "I" * 4 + "II", 0, 0, 0, 0, 0x99, 0, 0, 0, 0, 0, 0)
        oi, off = ti.parse_offset_info(data, 0, 15)
        assert oi.has_relation
        assert oi.relation_id == 0x99
        assert off == 40

    def test_fbarray_has_relation(self) -> None:
        # FbArray (0): 12 base + relid+4info(20) + 6 section u32 (24) + 6 i32 + 6 u32 = 104 bytes.
        data = (
            struct.pack("<HHII", 0, 0, 0, 0)
            + struct.pack("<I" + "I" * 4, 0xAB, 0, 0, 0, 0)
            + struct.pack("<6I", *([0] * 6))
            + struct.pack("<6i", *([0] * 6))
            + struct.pack("<6I", *([0] * 6))
        )
        oi, off = ti.parse_offset_info(data, 0, 0)
        assert oi.has_relation
        assert oi.relation_id == 0xAB
        assert off == 104


def _element(lid: int, crc: int, sdt: int, attr_flags: int, bitoff_flags: int, offset_info: bytes) -> bytes:
    # LID (u32 LE) + SymbolCrc (u32 LE) + Softdatatype (1B) + AttributeFlags (u16 BE!) +
    # BitoffsetinfoFlags (1B) + offset-info bytes.
    return struct.pack("<II", lid, crc) + bytes([sdt]) + struct.pack(">H", attr_flags) + bytes([bitoff_flags]) + offset_info


class TestVartypeElement:
    def test_scalar_int_std(self) -> None:
        # offsetinfotype = 8 (Std) lives in AttributeFlags bits 12..15 → 0x8000.
        data = _element(5, 0, int(ti.Softdatatype.INT), 0x8000, 0x00, struct.pack("<HH", 4, 20))
        el, off = ti.parse_vartype_element(data, 0)
        assert el.lid == 5
        assert el.softdatatype == int(ti.Softdatatype.INT)
        assert el.offsetinfotype == 8
        assert el.offset_info.opt_addr == 4 and el.offset_info.nonopt_addr == 20
        assert off == 16  # 4+4+1+2+1+4

    def test_bool_attribute_bitoffset(self) -> None:
        # AttributeFlags low 3 bits carry the optimized bit offset for a BOOL.
        data = _element(7, 0, int(ti.Softdatatype.BOOL), 0x8000 | 0x0003, 0x00, struct.pack("<HH", 1, 2))
        el, _ = ti.parse_vartype_element(data, 0)
        assert el.attribute_bitoffset == 3

    def test_bitoffsetinfo_accessors(self) -> None:
        # BitoffsetinfoFlags: 0x70 nonopt bitoffset (>>4), 0x08 classic, 0x07 opt bitoffset.
        data = _element(1, 0, int(ti.Softdatatype.BOOL), 0x8000, 0x58, struct.pack("<HH", 0, 0))  # 0x58 = 0101_1000
        el, _ = ti.parse_vartype_element(data, 0)
        assert el.nonopt_bitoffset == 5  # (0x58 & 0x70) >> 4
        assert el.classic is True  # 0x58 & 0x08
        assert el.opt_bitoffset == 0  # 0x58 & 0x07


class TestVartypeList:
    def test_two_elements_one_block(self) -> None:
        e1 = _element(1, 0, int(ti.Softdatatype.INT), 0x8000, 0, struct.pack("<HH", 0, 0))  # 16 bytes
        e2 = _element(2, 0, int(ti.Softdatatype.REAL), 0x8000, 0, struct.pack("<HH", 2, 4))  # 16 bytes
        block = e1 + e2  # 32 bytes
        # first block: BE-u16 blocklen, then u32-LE FirstId, then the elements; zero terminator.
        data = struct.pack(">H", len(block) + 4) + struct.pack("<I", 1) + block + struct.pack(">H", 0)
        elements, off = ti.parse_vartype_list(data, 0)
        assert [e.lid for e in elements] == [1, 2]
        assert elements[1].softdatatype == int(ti.Softdatatype.REAL)
        assert off == len(data)

    def test_multi_block_returns_all_elements(self) -> None:
        # A real PLC splits a long element list across multiple blocks. Only the
        # first block has the leading FirstId; later blocks are pure elements.
        e1 = _element(1, 0, int(ti.Softdatatype.INT), 0x8000, 0, struct.pack("<HH", 0, 0))  # 16 bytes
        e2 = _element(2, 0, int(ti.Softdatatype.REAL), 0x8000, 0, struct.pack("<HH", 2, 4))  # 16 bytes
        e3 = _element(3, 0, int(ti.Softdatatype.DINT), 0x8000, 0, struct.pack("<HH", 8, 12))  # 16 bytes
        e4 = _element(4, 0, int(ti.Softdatatype.BOOL), 0x8000, 0, struct.pack("<HH", 14, 16))  # 16 bytes
        e5 = _element(5, 0, int(ti.Softdatatype.BYTE), 0x8000, 0, struct.pack("<HH", 15, 17))  # 16 bytes
        # Three non-empty blocks before the zero terminator: (e1,e2), (e3), (e4,e5).
        data = _multiblock_vartype_list_bytes((e1, e2), (e3,), (e4, e5))
        elements, off = ti.parse_vartype_list(data, 0)
        # ALL elements across ALL blocks are returned, in order.
        assert [e.lid for e in elements] == [1, 2, 3, 4, 5]
        assert elements[2].softdatatype == int(ti.Softdatatype.DINT)
        # Cursor lands exactly past the zero terminator (no mid-stream stop).
        assert off == len(data)

    def test_multi_block_offset_feeds_following_field(self) -> None:
        # The bug left the cursor mid-stream on multi-block lists, corrupting the
        # next field. Verify the returned offset cleanly points at trailing data.
        e1 = _element(1, 0, int(ti.Softdatatype.INT), 0x8000, 0, struct.pack("<HH", 0, 0))
        e2 = _element(2, 0, int(ti.Softdatatype.REAL), 0x8000, 0, struct.pack("<HH", 2, 4))
        vt = _multiblock_vartype_list_bytes((e1,), (e2,))
        sentinel = b"\xde\xad\xbe\xef"
        data = vt + sentinel
        elements, off = ti.parse_vartype_list(data, 0)
        assert [e.lid for e in elements] == [1, 2]
        assert data[off:] == sentinel


def _obj_header(relid: int, class_id: int) -> bytes:
    return bytes([0xA1]) + struct.pack(">I", relid) + encode_uint32_vlq(class_id) + encode_uint32_vlq(0) + encode_uint32_vlq(0)


class TestParseObject:
    def test_header_attribute_vartype_varname(self) -> None:
        el = _element(10, 0, int(ti.Softdatatype.INT), 0x8000, 0, struct.pack("<HH", 2, 4))
        body = _obj_header(0x8A0E0001, 2574)
        # Attribute 1502 (TI_TComSize) = UDINT-ish; use a USINT PValue for the test.
        body += bytes([0xA3]) + encode_uint32_vlq(1502) + bytes([0x00, DataType.USINT, 24])
        body += bytes([0xAB]) + _vartype_list_bytes(el)
        body += bytes([0xAC]) + _varname_list_bytes("Speed")
        body += bytes([0xA2])  # TerminatingObject
        obj, off = ti.parse_object(body, 0)
        assert obj.relation_id == 0x8A0E0001
        assert obj.class_id == 2574
        assert obj.attributes[1502] == bytes([24])
        assert [e.lid for e in obj.vartype_list] == [10]
        assert obj.varname_list == ["Speed"]
        assert off == len(body)

    def test_nested_child_object(self) -> None:
        child = _obj_header(0x00000002, 511) + bytes([0xA2])
        parent = _obj_header(0x00000001, 534) + child + bytes([0xA2])
        obj, off = ti.parse_object(parent, 0)
        assert obj.relation_id == 1 and obj.class_id == 534
        assert len(obj.objects) == 1
        assert obj.objects[0].relation_id == 2 and obj.objects[0].class_id == 511
        assert off == len(parent)

    def test_object_list_two_siblings(self) -> None:
        a = _obj_header(1, 511) + bytes([0xA2])
        b = _obj_header(2, 511) + bytes([0xA2])
        objs, off = ti.parse_object_list(a + b, 0)
        assert [o.relation_id for o in objs] == [1, 2]
        assert off == len(a + b)


def _vte(
    lid: int,
    sdt,
    oi: "ti.OffsetInfo",
    attr_flags: int = 0,
    bitoff: int = 0,
    symbol_crc: int = 0,
) -> "ti.VartypeListElement":
    return ti.VartypeListElement(
        lid=lid,
        symbol_crc=symbol_crc,
        softdatatype=int(sdt),
        attribute_flags=attr_flags,
        bitoffsetinfo_flags=bitoff,
        offset_info=oi,
    )


def _root(name: str, relid_db: int, ti_relid: int) -> "ti.Node":
    return ti.Node(node_type=ti.NodeType.ROOT, name=name, access_id=relid_db, relation_id=ti_relid)


class TestTreeBuilder:
    def test_scalar_leaf(self) -> None:
        root = _root("DB1", 0x8A0E0001, 0x100)
        type_obj = ti.PObject(
            relation_id=0x100,
            vartype_list=[_vte(10, ti.Softdatatype.INT, ti.OffsetInfo(code=8, opt_addr=2, nonopt_addr=4))],
            varname_list=["Speed"],
        )
        ti.build_tree([root], [type_obj])
        infos = ti.build_flat_list([root])
        assert len(infos) == 1
        v = infos[0]
        assert v.name == "DB1.Speed"
        assert v.access_sequence == "8A0E0001.A"  # DB relid + LID 0xA
        assert v.softdatatype == int(ti.Softdatatype.INT)
        assert v.opt_address == 2 and v.nonopt_address == 4

    def test_nested_struct_offsets_accumulate(self) -> None:
        root = _root("DB1", 0x8A0E0001, 0x100)
        outer = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    5,
                    ti.Softdatatype.STRUCT,
                    ti.OffsetInfo(code=12, opt_addr=10, nonopt_addr=100, relation_id=0x200, has_relation=True),
                )
            ],
            varname_list=["Motor"],
        )
        inner = ti.PObject(
            relation_id=0x200,
            vartype_list=[_vte(3, ti.Softdatatype.INT, ti.OffsetInfo(code=8, opt_addr=6, nonopt_addr=8))],
            varname_list=["Rpm"],
        )
        ti.build_tree([root], [outer, inner])
        infos = ti.build_flat_list([root])
        assert len(infos) == 1
        v = infos[0]
        assert v.name == "DB1.Motor.Rpm"
        assert v.access_sequence == "8A0E0001.5.3"
        assert v.opt_address == 16  # 10 (Motor) + 6 (Rpm)
        assert v.nonopt_address == 108

    def test_basic_array_elements(self) -> None:
        root = _root("DB1", 0x8A0E0001, 0x100)
        type_obj = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    9,
                    ti.Softdatatype.INT,
                    ti.OffsetInfo(code=10, opt_addr=20, nonopt_addr=40, array_element_count=3, array_lower_bound=0, is_1dim=True),
                    symbol_crc=0x12345678,
                )
            ],
            varname_list=["Vals"],
        )
        ti.build_tree([root], [type_obj])
        infos = ti.build_flat_list([root])
        assert [v.name for v in infos] == ["DB1.Vals[0]", "DB1.Vals[1]", "DB1.Vals[2]"]
        assert [v.access_sequence for v in infos] == ["8A0E0001.9.0", "8A0E0001.9.1", "8A0E0001.9.2"]
        assert [v.opt_address for v in infos] == [20, 22, 24]  # base + i*2 (INT stride)
        assert all(v.symbol_crc == 0x12345678 for v in infos)
        assert all(v.array_dimensions == ((0, 3),) for v in infos)

    def test_struct_array_inserts_extra_one(self) -> None:
        root = _root("DB1", 0x8A0E0001, 0x100)
        outer = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    7,
                    ti.Softdatatype.STRUCT,
                    ti.OffsetInfo(
                        code=13,
                        opt_addr=0,
                        nonopt_addr=0,
                        array_element_count=2,
                        array_lower_bound=0,
                        relation_id=0x300,
                        has_relation=True,
                        is_1dim=True,
                    ),
                )
            ],
            varname_list=["Items"],
        )
        item_type = ti.PObject(
            relation_id=0x300,
            attributes={1502: struct.pack(">I", 8)},  # TI_TComSize = 8-byte struct stride
            vartype_list=[_vte(2, ti.Softdatatype.REAL, ti.OffsetInfo(code=8, opt_addr=0, nonopt_addr=0))],
            varname_list=["X"],
        )
        ti.build_tree([root], [outer, item_type])
        infos = ti.build_flat_list([root])
        assert [v.name for v in infos] == ["DB1.Items[0].X", "DB1.Items[1].X"]
        # StructArray inserts a ".1" between the array index id and the member LID.
        assert [v.access_sequence for v in infos] == ["8A0E0001.7.0.1.2", "8A0E0001.7.1.1.2"]
        assert [v.opt_address for v in infos] == [0, 8]  # element stride 8
        assert all(v.array_dimensions == ((0, 2),) for v in infos)


class TestMDimArrays:
    def test_basic_mdim_array_ordering_bounds_and_offsets(self) -> None:
        # ARRAY[1..3, 10..11] of INT — dim0 (fastest, in-memory) has 3 elements, dim1 has 2.
        # The name lists the highest dimension first: [dim1, dim0].
        root = _root("DB1", 0x8A0E0001, 0x100)
        type_obj = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    9,
                    ti.Softdatatype.INT,
                    ti.OffsetInfo(
                        code=11,
                        opt_addr=20,
                        nonopt_addr=40,
                        array_element_count=6,
                        mdim_element_count=[3, 2, 0, 0, 0, 0],
                        mdim_lower_bounds=[1, 10, 0, 0, 0, 0],
                        is_mdim=True,
                    ),
                )
            ],
            varname_list=["Grid"],
        )
        ti.build_tree([root], [type_obj])
        infos = ti.build_flat_list([root])
        assert [v.name for v in infos] == [
            "DB1.Grid[10,1]",
            "DB1.Grid[10,2]",
            "DB1.Grid[10,3]",
            "DB1.Grid[11,1]",
            "DB1.Grid[11,2]",
            "DB1.Grid[11,3]",
        ]
        assert [v.access_sequence for v in infos] == [
            "8A0E0001.9.0",
            "8A0E0001.9.1",
            "8A0E0001.9.2",
            "8A0E0001.9.3",
            "8A0E0001.9.4",
            "8A0E0001.9.5",
        ]
        assert [v.opt_address for v in infos] == [20, 22, 24, 26, 28, 30]  # base + (n-1)*2
        assert [v.nonopt_address for v in infos] == [40, 42, 44, 46, 48, 50]
        assert all(v.array_dimensions == ((1, 3), (10, 2)) for v in infos)

    def test_bbool_mdim_access_id_aligns_to_byte(self) -> None:
        # ARRAY[0..2, 0..1] of BOOL stored as BBOOL: each row of 3 bits rounds up to a byte,
        # so the access-id of the second row starts at 8, not 3. Offsets stay linear (n-1).
        root = _root("DB1", 0x8A0E0001, 0x100)
        type_obj = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    7,
                    ti.Softdatatype.BBOOL,
                    ti.OffsetInfo(
                        code=11,
                        opt_addr=0,
                        nonopt_addr=0,
                        array_element_count=6,
                        mdim_element_count=[3, 2, 0, 0, 0, 0],
                        mdim_lower_bounds=[0, 0, 0, 0, 0, 0],
                        is_mdim=True,
                    ),
                )
            ],
            varname_list=["Flags"],
        )
        ti.build_tree([root], [type_obj])
        infos = ti.build_flat_list([root])
        assert [v.name for v in infos] == [
            "DB1.Flags[0,0]",
            "DB1.Flags[0,1]",
            "DB1.Flags[0,2]",
            "DB1.Flags[1,0]",
            "DB1.Flags[1,1]",
            "DB1.Flags[1,2]",
        ]
        assert [v.access_sequence for v in infos] == [
            "8A0E0001.7.0",
            "8A0E0001.7.1",
            "8A0E0001.7.2",
            "8A0E0001.7.8",
            "8A0E0001.7.9",
            "8A0E0001.7.A",
        ]

    def test_struct_mdim_array_inserts_extra_one(self) -> None:
        # ARRAY[0..1, 0..1] of <struct> — StructArray nodes insert ".1" and stride by TComSize.
        root = _root("DB1", 0x8A0E0001, 0x100)
        outer = ti.PObject(
            relation_id=0x100,
            vartype_list=[
                _vte(
                    7,
                    ti.Softdatatype.STRUCT,
                    ti.OffsetInfo(
                        code=14,
                        opt_addr=0,
                        nonopt_addr=0,
                        array_element_count=4,
                        mdim_element_count=[2, 2, 0, 0, 0, 0],
                        mdim_lower_bounds=[0, 0, 0, 0, 0, 0],
                        relation_id=0x300,
                        has_relation=True,
                        is_mdim=True,
                    ),
                )
            ],
            varname_list=["Cells"],
        )
        item_type = ti.PObject(
            relation_id=0x300,
            attributes={1502: struct.pack(">I", 8)},  # TI_TComSize = 8-byte struct stride
            vartype_list=[_vte(2, ti.Softdatatype.REAL, ti.OffsetInfo(code=8, opt_addr=0, nonopt_addr=0))],
            varname_list=["X"],
        )
        ti.build_tree([root], [outer, item_type])
        infos = ti.build_flat_list([root])
        assert [v.name for v in infos] == [
            "DB1.Cells[0,0].X",
            "DB1.Cells[0,1].X",
            "DB1.Cells[1,0].X",
            "DB1.Cells[1,1].X",
        ]
        assert [v.access_sequence for v in infos] == [
            "8A0E0001.7.0.1.2",
            "8A0E0001.7.1.1.2",
            "8A0E0001.7.2.1.2",
            "8A0E0001.7.3.1.2",
        ]
        assert [v.opt_address for v in infos] == [0, 8, 16, 24]  # (n-1) * TComSize


class TestExtractTypeInfoObjects:
    def test_finds_container_children(self) -> None:
        child1 = _obj_header(0x100, 511) + bytes([0xA2])
        child2 = _obj_header(0x200, 511) + bytes([0xA2])
        container = _obj_header(0x537, ti.CLASS_OMS_TYPE_INFO_CONTAINER) + child1 + child2 + bytes([0xA2])
        response = bytes([0x00]) + container  # leading return-value VLQ + the container object
        objs = ti.extract_type_info_objects(response)
        assert [o.relation_id for o in objs] == [0x100, 0x200]

    def test_no_container_returns_empty(self) -> None:
        response = bytes([0x00]) + _obj_header(1, 999) + bytes([0xA2])
        assert ti.extract_type_info_objects(response) == []

    def test_skips_preamble_before_first_object(self) -> None:
        # Real EXPLORE(537) responses carry several preamble bytes between the return-value
        # and the first StartOfObject (0xA1) — the parser must skip to it.
        child = _obj_header(0x100, 511) + bytes([0xA2])
        container = _obj_header(0x219, ti.CLASS_OMS_TYPE_INFO_CONTAINER) + child + bytes([0xA2])
        response = bytes([0x00, 0x00, 0x00, 0x00, 0xC9, 0x4F]) + container  # 6-byte preamble
        objs = ti.extract_type_info_objects(response)
        assert [o.relation_id for o in objs] == [0x100]


class TestCapturedSystemTypes:
    """EXPLORE of the OMS type-info container from an S7-1500 (6ES7 512-1CK01-0AB0, FW V2.9).

    Cut to the type objects of two DBs: 0x92000053 is ``DB_SysTypeArrays`` (DB83, optimized
    arrays of system types) and 0x92000054 is ``DB_SysTypes_Std`` (DB84, standard access).
    The bytes around the container's children are unchanged; its other 453 children are
    left out. A raw ``db_read`` of DB84 on that PLC matched every non-optimized offset
    derived here.
    """

    REPLY = bytes.fromhex(
        "00000000c98276a10000021984163000a38169001500a192000053837f2000a38169001500a38308000c80000003a383"
        "14000400a384110005c0cbc0eae9d8cee96ca38b5e00042aa38b5f000801a384630017000006068c070004008c080004"
        "008c090004811400a3831a00058cba98af98aec9cf00a3831c000b0001a3831d000400ab00e40200008009000000303e"
        "606b95aac000000000001c0000000000000000000000030000000a000000a285a75fd0aac00000000000220000000600"
        "000000000000020000000b0000009334bbd0a0aac00000000000260000000a00000000000000020000000c0000004c7b"
        "0dbeabaac00000000000040000000e00000000000000020000000d000000654610e181aac000000000000c0000001600"
        "000001000000020000000e00000015d0b1b3c8aac000000000002a0000001e00000000000000030000000f00000017f1"
        "a720c9aac00000000000140000002200000000000000020000000000ac003d05614877496f0006614462416e79000661"
        "4f62416e79000861436f6e6e5249640009614576656e74416e7900076155614d61736b00066155614c656e000000a2a1"
        "92000054837f2000a38169001500a38308000c80000003a38314000400a3841100058ca999d0e193d788f1a38b5e0004"
        "32a38b5f000801a384630017000006068c070004328c080004008c0900040400a3831a00058cba98afa98eacd410a383"
        "1c000b0001a3831d000400ab00d4020000800900000059f3a8ae018ac008000000000a0000005173a58f958ac0080200"
        "02000b000000c245c910028ac008040004000c0000006218e76bc88ac008050005000d000000abaae6c8a08ac0080600"
        "06000e00000036e497ccab8ac008080008000f000000c9fc84bb028ac0080c000c00100000003fcbc1a0818ac0080e00"
        "0e0011000000068a3e4dd08ac0081200120012000000c7ccfeb2028ac0081400140013000000303e606b95aac0080000"
        "00001600000016000000000000000300000014000000cc75b319028ac0081c001c000070150000004c7b0dbeabaac008"
        "000000001e0000001e0000000000000002000000160000009334bbd0a0aac00800000000260000002600000000000000"
        "020000001700000015d0b1b3c8aac008000000002a0000002a000000000000000300000018000000a9a972ffc98ac008"
        "2e002e000000ac00730262300005764877496f0002633000077655614d61736b0006764f62416e79000876436f6e6e52"
        "4964000263310009764576656e74416e790006764462416e79000263320005614877496f00026333000861436f6e6e52"
        "49640006614f62416e7900076155614d61736b00067655614c656e000000a2a200000000"
    )

    def test_standard_access_offsets_match_db_read(self) -> None:
        root = _root("DB_SysTypes_Std", 0x8A0E0054, 0x92000054)
        ti.build_tree([root], ti.extract_type_info_objects(self.REPLY))
        infos = ti.build_flat_list([root])
        assert {v.name: (v.softdatatype, v.nonopt_address, v.nonopt_bitoffset, v.access_sequence) for v in infos} == {
            "DB_SysTypes_Std.b0": (ti.Softdatatype.BOOL, 0, 0, "8A0E0054.9"),
            "DB_SysTypes_Std.vHwIo": (ti.Softdatatype.HW_IO, 2, 0, "8A0E0054.A"),
            "DB_SysTypes_Std.c0": (ti.Softdatatype.BYTE, 4, 0, "8A0E0054.B"),
            "DB_SysTypes_Std.vUaMask": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 5, 0, "8A0E0054.C"),
            "DB_SysTypes_Std.vObAny": (ti.Softdatatype.OB_ANY, 6, 0, "8A0E0054.D"),
            "DB_SysTypes_Std.vConnRId": (ti.Softdatatype.CONN_R_ID, 8, 0, "8A0E0054.E"),
            "DB_SysTypes_Std.c1": (ti.Softdatatype.BYTE, 12, 0, "8A0E0054.F"),
            "DB_SysTypes_Std.vEventAny": (ti.Softdatatype.EVENT_ANY, 14, 0, "8A0E0054.10"),
            "DB_SysTypes_Std.vDbAny": (ti.Softdatatype.DB_ANY, 18, 0, "8A0E0054.11"),
            "DB_SysTypes_Std.c2": (ti.Softdatatype.BYTE, 20, 0, "8A0E0054.12"),
            "DB_SysTypes_Std.aHwIo[0]": (ti.Softdatatype.HW_IO, 22, 0, "8A0E0054.13.0"),
            "DB_SysTypes_Std.aHwIo[1]": (ti.Softdatatype.HW_IO, 24, 0, "8A0E0054.13.1"),
            "DB_SysTypes_Std.aHwIo[2]": (ti.Softdatatype.HW_IO, 26, 0, "8A0E0054.13.2"),
            "DB_SysTypes_Std.c3": (ti.Softdatatype.BYTE, 28, 0, "8A0E0054.14"),
            "DB_SysTypes_Std.aConnRId[0]": (ti.Softdatatype.CONN_R_ID, 30, 0, "8A0E0054.15.0"),
            "DB_SysTypes_Std.aConnRId[1]": (ti.Softdatatype.CONN_R_ID, 34, 0, "8A0E0054.15.1"),
            "DB_SysTypes_Std.aObAny[0]": (ti.Softdatatype.OB_ANY, 38, 0, "8A0E0054.16.0"),
            "DB_SysTypes_Std.aObAny[1]": (ti.Softdatatype.OB_ANY, 40, 0, "8A0E0054.16.1"),
            "DB_SysTypes_Std.aUaMask[0]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 42, 0, "8A0E0054.17.0"),
            "DB_SysTypes_Std.aUaMask[1]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 43, 0, "8A0E0054.17.1"),
            "DB_SysTypes_Std.aUaMask[2]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 44, 0, "8A0E0054.17.2"),
            "DB_SysTypes_Std.vUaLen": (ti.Softdatatype.OPC_UA_BYTESTRINGACTUALLENGTH, 46, 0, "8A0E0054.18"),
        }

    def test_optimized_arrays_step_by_element_size(self) -> None:
        root = _root("DB_SysTypeArrays", 0x8A0E0053, 0x92000053)
        ti.build_tree([root], ti.extract_type_info_objects(self.REPLY))
        infos = ti.build_flat_list([root])
        assert {v.name: (v.softdatatype, v.opt_address, v.access_sequence, v.array_dimensions) for v in infos} == {
            "DB_SysTypeArrays.aHwIo[0]": (ti.Softdatatype.HW_IO, 28, "8A0E0053.9.0", ((0, 3),)),
            "DB_SysTypeArrays.aHwIo[1]": (ti.Softdatatype.HW_IO, 30, "8A0E0053.9.1", ((0, 3),)),
            "DB_SysTypeArrays.aHwIo[2]": (ti.Softdatatype.HW_IO, 32, "8A0E0053.9.2", ((0, 3),)),
            "DB_SysTypeArrays.aDbAny[0]": (ti.Softdatatype.DB_ANY, 34, "8A0E0053.A.0", ((0, 2),)),
            "DB_SysTypeArrays.aDbAny[1]": (ti.Softdatatype.DB_ANY, 36, "8A0E0053.A.1", ((0, 2),)),
            "DB_SysTypeArrays.aObAny[0]": (ti.Softdatatype.OB_ANY, 38, "8A0E0053.B.0", ((0, 2),)),
            "DB_SysTypeArrays.aObAny[1]": (ti.Softdatatype.OB_ANY, 40, "8A0E0053.B.1", ((0, 2),)),
            "DB_SysTypeArrays.aConnRId[0]": (ti.Softdatatype.CONN_R_ID, 4, "8A0E0053.C.0", ((0, 2),)),
            "DB_SysTypeArrays.aConnRId[1]": (ti.Softdatatype.CONN_R_ID, 8, "8A0E0053.C.1", ((0, 2),)),
            "DB_SysTypeArrays.aEventAny[1]": (ti.Softdatatype.EVENT_ANY, 12, "8A0E0053.D.0", ((1, 2),)),
            "DB_SysTypeArrays.aEventAny[2]": (ti.Softdatatype.EVENT_ANY, 16, "8A0E0053.D.1", ((1, 2),)),
            "DB_SysTypeArrays.aUaMask[0]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 42, "8A0E0053.E.0", ((0, 3),)),
            "DB_SysTypeArrays.aUaMask[1]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 43, "8A0E0053.E.1", ((0, 3),)),
            "DB_SysTypeArrays.aUaMask[2]": (ti.Softdatatype.OPC_UA_LOCALIZEDTEXTENCODINGMASK, 44, "8A0E0053.E.2", ((0, 3),)),
            "DB_SysTypeArrays.aUaLen[0]": (ti.Softdatatype.OPC_UA_BYTESTRINGACTUALLENGTH, 20, "8A0E0053.F.0", ((0, 2),)),
            "DB_SysTypeArrays.aUaLen[1]": (ti.Softdatatype.OPC_UA_BYTESTRINGACTUALLENGTH, 24, "8A0E0053.F.1", ((0, 2),)),
        }


class TestCapturedBoolArray:
    """The type info of ``DB_AllTypes_Std`` (DB41, standard access) from an S7-1500 (FW V2.9).

    See tests/fixtures/s7_1500_db_alltypes_std.py for the capture.
    """

    def test_bool_arrays_match_tia_offsets(self) -> None:
        root = _root("DB_AllTypes_Std", 0x8A0E0029, 0x92000029)
        ti.build_tree([root], ti.extract_type_info_objects(alltypes_std.EXPLORE_TYPE_INFO))
        infos = {v.name.removeprefix("DB_AllTypes_Std."): v for v in ti.build_flat_list([root])}
        tia = alltypes_std.TIA
        assert {
            name: (f"{infos[name].nonopt_address}.{infos[name].nonopt_bitoffset}", infos[name].access_sequence[9:])
            for name in tia
        } == {name: (offset, access) for name, (offset, _, access) in tia.items()}
        raw, raw_offset = alltypes_std.RAW, alltypes_std.RAW_OFFSET
        assert {
            name: bool((raw[infos[name].nonopt_address - raw_offset] >> infos[name].nonopt_bitoffset) & 1)
            for name, (_, value, _) in tia.items()
            if value is not None
        } == {name: value for name, (_, value, _) in tia.items() if value is not None}
