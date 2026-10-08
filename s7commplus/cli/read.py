"""``s7commplus read``: read named tags and decode scalar values."""

from __future__ import annotations

import argparse

from ..catalog import TagResult
from ._common import EXIT_FAILED, EXIT_OK, Subparsers, add_command, add_connection_options, open_client, print_json


def register(subparsers: Subparsers) -> None:
    """Add the ``read`` command."""
    parser = add_command(subparsers, "read", "read one or more named tags")
    add_connection_options(parser)
    parser.add_argument("names", nargs="+", metavar="NAME")
    parser.add_argument("--json", action="store_true", help="emit JSON (a NaN or infinite REAL/LREAL becomes null)")
    parser.set_defaults(handler=run)


def _format_result(result: TagResult) -> str:
    if result.error is not None:
        return f"{result.tag.name} = <error: {result.error}>"
    assert result.value is not None
    decoded = result.tag.decode_value(result.value)
    if isinstance(decoded, bytes):
        return f"{result.tag.name} = {decoded.hex()}"
    return f"{result.tag.name} = {decoded}"


def run(args: argparse.Namespace) -> int:
    """Print each tag's decoded value; exit 1 if any tag could not be read."""
    with open_client(args) as client:
        results = client.read_tags(list(args.names))
    if args.json:
        print_json(
            [
                {
                    "name": result.tag.name,
                    "value": None if result.error is not None else result.tag.decode_value(result.value or b""),
                    "error": None if result.error is None else str(result.error),
                }
                for result in results
            ]
        )
    else:
        for result in results:
            print(_format_result(result))
    return EXIT_OK if all(result.success for result in results) else EXIT_FAILED
