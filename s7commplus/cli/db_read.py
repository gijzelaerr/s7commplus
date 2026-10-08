"""``s7commplus db-read``: read raw bytes from a data block."""

from __future__ import annotations

import argparse

from ._common import EXIT_OK, Subparsers, add_command, int_in_range, open_client, parse_db_number, parse_db_start


def register(subparsers: Subparsers) -> None:
    """Add the ``db-read`` command."""
    parser = add_command(subparsers, "db-read", "read raw bytes from a DB")
    parser.add_argument("db", type=parse_db_number, metavar="DB")
    parser.add_argument("start", type=parse_db_start, metavar="START")
    parser.add_argument("size", type=int_in_range("SIZE", 1, 0xFFFFFFFF), metavar="SIZE")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    """Print the bytes read as hex."""
    with open_client(args) as client:
        data = client.db_read(args.db, args.start, args.size)
    print(data.hex())
    return EXIT_OK
