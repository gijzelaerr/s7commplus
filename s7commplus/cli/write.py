"""``s7commplus write``: write one named tag."""

from __future__ import annotations

import argparse
import struct

from ._common import EXIT_OK, Subparsers, add_command, add_connection_options, int_in_range, open_client, parse_hex


def _parse_real(text: str) -> float:
    """An argparse ``type`` accepting a value a 32-bit REAL can hold."""
    try:
        value = float(text)
        struct.pack(">f", value)  # OverflowError beyond the REAL range
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError(f"not a REAL (32-bit float) value: {text!r}") from None
    return value


def register(subparsers: Subparsers) -> None:
    """Add the ``write`` command."""
    parser = add_command(subparsers, "write", "write one named tag")
    add_connection_options(parser)
    parser.add_argument("name", metavar="NAME")
    value = parser.add_mutually_exclusive_group(required=True)
    value.add_argument("--hex", dest="hex_value", type=parse_hex, metavar="BYTES", help="raw big-endian bytes")
    value.add_argument("--bool", dest="bool_value", type=int, choices=(0, 1), help="BOOL (1 byte)")
    value.add_argument("--int", dest="int_value", type=int_in_range("INT", -(2**15), 2**15 - 1), help="INT (2 bytes)")
    value.add_argument("--dint", dest="dint_value", type=int_in_range("DINT", -(2**31), 2**31 - 1), help="DINT (4 bytes)")
    value.add_argument("--real", dest="real_value", type=_parse_real, help="REAL (4 bytes)")
    value.add_argument("--string", dest="string_value", help="STRING/WSTRING text")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    """Encode the value, write it and echo the bytes written."""
    if args.hex_value is not None:
        data = args.hex_value
    elif args.bool_value is not None:
        data = struct.pack(">?", bool(args.bool_value))
    elif args.int_value is not None:
        data = struct.pack(">h", args.int_value)
    elif args.dint_value is not None:
        data = struct.pack(">i", args.dint_value)
    elif args.real_value is not None:
        data = struct.pack(">f", args.real_value)
    else:
        data = args.string_value.encode("utf-8")
    with open_client(args) as client:
        client.write_tag(args.name, data)
    print(f"{args.name} = {data.hex()}")
    return EXIT_OK
