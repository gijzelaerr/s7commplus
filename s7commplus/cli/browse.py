"""``s7commplus browse``: list the PLC's symbolic tags."""

from __future__ import annotations

import argparse

from ._common import EXIT_OK, Subparsers, add_command, add_connection_options, open_client, print_json


def register(subparsers: Subparsers) -> None:
    """Add the ``browse`` command."""
    parser = add_command(subparsers, "browse", "list the PLC's symbolic tags")
    add_connection_options(parser)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    """Print each tag's name, wire data type and access sequence, or all browse fields as JSON."""
    with open_client(args) as client:
        tags = client.browse()
    if args.json:
        print_json(tags)
        return EXIT_OK
    for tag in tags:
        print(f"{tag.get('name', '')}\t{tag.get('data_type', '')}\t{tag.get('access_sequence', '')}")
    return EXIT_OK
