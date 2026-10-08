"""``s7commplus db-write``: write raw bytes to a data block."""

from __future__ import annotations

import argparse

from ._common import EXIT_OK, Subparsers, add_command, open_client, parse_db_number, parse_db_start, parse_hex


def register(subparsers: Subparsers) -> None:
    """Add the ``db-write`` command."""
    parser = add_command(subparsers, "db-write", "write raw bytes to a DB")
    parser.add_argument("db", type=parse_db_number, metavar="DB")
    parser.add_argument("start", type=parse_db_start, metavar="START")
    parser.add_argument("--hex", dest="hex_value", type=parse_hex, required=True, metavar="BYTES")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    """Write the bytes and echo the range written."""
    with open_client(args) as client:
        client.db_write(args.db, args.start, args.hex_value)
    print(f"DB{args.db}[{args.start}:{args.start + len(args.hex_value)}] = {args.hex_value.hex()}")
    return EXIT_OK
