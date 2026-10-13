"""Parsers of PLC replies fail cleanly on malformed input.

PLC data is untrusted: a truncated or corrupted reply must raise ``ValueError``
or an ``S7Error`` (or, where a parser documents it, ``RuntimeError`` for a PLC
error code), never ``struct.error``, ``IndexError``, ``zlib.error`` or an XML
``ParseError``, and never hang or exhaust memory.

The fixed inputs below are the smallest crashing inputs a fuzzing run found
against these parsers; the property tests keep looking for new ones.
"""

import zlib
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from s7commplus import alarm, blob_decompressor, codec, subscription, tag_browser, typeinfo
from s7commplus.client import (
    _parse_cpu_state,
    _parse_explore_datablocks,
    _parse_read_response,
    _parse_substreamed_read_response,
    _parse_write_response,
    _parse_write_response_errors,
)
from s7commplus.connection import (
    _parse_get_var_substreamed_response,
    _parse_protection_level_response,
    _validate_response_header,
)
from s7commplus.error import S7Error
from s7commplus.protocol import FunctionCode

# (name, parser, extra exceptions the parser documents for a valid but refused reply)
PARSERS: list[tuple[str, Callable[[bytes], Any], tuple[type[BaseException], ...]]] = [
    ("decode_header", codec.decode_header, ()),
    ("decode_response_header", codec.decode_response_header, ()),
    ("decode_pvalue_to_bytes", lambda data: codec.decode_pvalue_to_bytes(data, 0), ()),
    ("parse_create_object_attributes", codec.parse_create_object_attributes, ()),
    ("parse_create_object_session_id", codec.parse_create_object_session_id, ()),
    ("parse_or_raise_for_return_value", lambda data: codec.parse_or_raise_for_return_value(data, "test"), ()),
    ("parse_server_session_version", codec.parse_server_session_version, ()),
    ("parse_alarm_explore_response", alarm.parse_alarm_explore_response, ()),
    ("parse_alarm_notification", alarm.parse_alarm_notification, ()),
    ("notification_subscription_id", subscription.notification_subscription_id, ()),
    ("parse_subscription_notification", subscription.parse_subscription_notification, ()),
    ("extract_type_info_objects", typeinfo.extract_type_info_objects, ()),
    ("block_interface_from_explore", tag_browser.block_interface_from_explore, ()),
    ("datablocks_from_explore", tag_browser.datablocks_from_explore, ()),
    ("tags_from_explore", tag_browser.tags_from_explore, ()),
    ("find_and_decompress", blob_decompressor.find_and_decompress, ()),
    # decompress_blob documents zlib.error for a stream that does not inflate.
    ("decompress_blob", blob_decompressor.decompress_blob, (zlib.error,)),
    ("_parse_cpu_state", _parse_cpu_state, ()),
    ("_parse_explore_datablocks", _parse_explore_datablocks, ()),
    # The read and write parsers report a PLC error code as RuntimeError.
    ("_parse_read_response", _parse_read_response, (RuntimeError,)),
    ("_parse_substreamed_read_response", _parse_substreamed_read_response, (RuntimeError,)),
    ("_parse_write_response", _parse_write_response, (RuntimeError,)),
    ("_parse_write_response_errors", _parse_write_response_errors, (RuntimeError,)),
    ("_parse_get_var_substreamed_response", _parse_get_var_substreamed_response, ()),
    ("_parse_protection_level_response", _parse_protection_level_response, ()),
    (
        "_validate_response_header",
        lambda data: _validate_response_header(data, FunctionCode.GET_MULTI_VARIABLES, 1),
        (),
    ),
]


def _call(parser: Callable[[bytes], Any], data: bytes, allowed: tuple[type[BaseException], ...]) -> None:
    try:
        parser(data)
    except (ValueError, S7Error, *allowed):
        pass


# Smallest inputs that made each parser crash before it was hardened.
CRASHERS = [
    # A UDINT PValue whose VLQ carries more than 32 bits.
    ("decode_pvalue_to_bytes", lambda data: codec.decode_pvalue_to_bytes(data, 0), "e113908597f6319f05820b"),
    # An alarm object cut off inside its relation id.
    ("parse_alarm_explore_response", alarm.parse_alarm_explore_response, "0017000001a1a13a"),
    # A type-info object cut off inside its relation id, and one cut off in a list.
    ("extract_type_info_objects", typeinfo.extract_type_info_objects, "69a1"),
    (
        "extract_type_info_objects",
        typeinfo.extract_type_info_objects,
        "052f1284b0f60994a7a1865f1b10ad63cdfbc32754c81d907aac6f6c56",
    ),
    # Interface streams that inflate to broken XML, or do not inflate.
    ("block_interface_from_explore", tag_browser.block_interface_from_explore, "787d66052b13ad58d9"),
    (
        "block_interface_from_explore",
        tag_browser.block_interface_from_explore,
        "787d66052b13ad58d96e5b470cfd15c30f7d6335c3d9d3d8a3a3a3a3a3a3406ca768801629da200f7d11666d8d3a9122c946d0af2fe"
        "76eba8b65bb485f6cdd8567381c92e7f03edf19edb2314e0fe472c24067ab9683",
    ),
    ("tags_from_explore", tag_browser.tags_from_explore, "787dce9b821b"),
    (
        "tags_from_explore",
        tag_browser.tags_from_explore,
        "787dce9b821bb3b1afc8cd51284b2d2acecccf0366263d6031909a979c9f9299976eab545a92a66ba1646f6783ae0bd60072538bb"
        "2538b685580e18c4823628a2f2c81010f0a143f9400633109681c764f181aa2f902a892125f",
    ),
]


@pytest.mark.parametrize(("name", "parser", "hex_input"), CRASHERS, ids=[f"{c[0]}-{i}" for i, c in enumerate(CRASHERS)])
def test_known_crashing_input_raises_value_error(name: str, parser: Callable[[bytes], Any], hex_input: str) -> None:
    with pytest.raises(ValueError):
        parser(bytes.fromhex(hex_input))


def test_read_response_with_a_huge_item_number_raises_instead_of_allocating() -> None:
    # ReturnValue 0, then item number 0xA3A3A3A3 (a 5-byte VLQ) and a NULL value.
    # The parser used to build a list as long as that number: about 2.7 billion
    # entries from 15 bytes, which hung the caller and exhausted memory.
    reply = bytes.fromhex("0000a3a3a3a3a3a3a3a30500000000")
    with pytest.raises(ValueError, match="answers only"):
        _parse_read_response(reply)


def test_read_response_with_items_numbered_one_to_n_still_parses() -> None:
    # ReturnValue 0, item 1 = USINT 0x2A, item 2 = USINT 0x07, end of values,
    # then an empty error list.
    reply = bytes.fromhex("000100022a020002070000")
    assert _parse_read_response(reply) == [b"\x2a", b"\x07"]


@pytest.mark.parametrize(("name", "parser", "allowed"), PARSERS, ids=[p[0] for p in PARSERS])
@settings(max_examples=150, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.binary(max_size=128))
def test_parser_fails_cleanly_on_arbitrary_bytes(
    name: str, parser: Callable[[bytes], Any], allowed: tuple[type[BaseException], ...], data: bytes
) -> None:
    _call(parser, data, allowed)


# Zlib headers the metadata parsers look for, so generated input reaches the
# decompression and XML stages instead of stopping at the header search.
_ZLIB_PREFIXES = [bytes.fromhex("787d66052b13"), bytes.fromhex("787dce9b821b"), bytes.fromhex("78da")]
_METADATA_PARSERS = [p for p in PARSERS if p[0].endswith("_from_explore") or "decompress" in p[0]]


@pytest.mark.parametrize(("name", "parser", "allowed"), _METADATA_PARSERS, ids=[p[0] for p in _METADATA_PARSERS])
@settings(max_examples=150, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(prefix=st.sampled_from(_ZLIB_PREFIXES), rest=st.binary(max_size=256))
def test_metadata_parser_fails_cleanly_on_corrupt_streams(
    name: str, parser: Callable[[bytes], Any], allowed: tuple[type[BaseException], ...], prefix: bytes, rest: bytes
) -> None:
    _call(parser, prefix + rest, allowed)
