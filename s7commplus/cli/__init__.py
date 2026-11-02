"""Command-line interface for s7commplus.

A thin, dependency-free wrapper around :class:`~s7commplus.Client` for the
common field tasks: browse the symbol tree, read and write named tags, read and
write raw DB bytes, and read the CPU state.

The PLC password is never logged or echoed. Give it through the
``S7COMMPLUS_PASSWORD`` environment variable or type it at the prompt that
``--ask-password`` shows; ``--password VALUE`` also works, but leaves the
password in the process list and the shell history.

``--tls-ca``, ``--tls-cert``, ``--tls-key`` and ``--tls-cert-fingerprint``
(``--pin``) imply ``--tls``: asking for a certificate check never leaves the
connection in plaintext.

``-v``/``--verbose`` before the command sends the library's log records to
stderr: INFO with ``-v``, DEBUG with ``-vv``. DEBUG output contains every
protocol frame in hex, including the authentication exchange, so review it
before sharing it.

Exit status: 0 on success; 1 when the operation fails (a connection, protocol,
TLS, certificate or authentication error, a certificate or key file that cannot
be loaded, a ``ValueError`` the library raises once connected, or a PLC that
rejects a read or write); 2 for a usage error (invalid arguments or values,
found before connecting, a missing certificate or key file, or an unknown tag);
130 when interrupted.

Each command is a module of this package with a ``register(subparsers)``
function that adds the command's subparser and sets its handler;
:data:`COMMANDS` lists them in the order ``--help`` shows them. A command that
talks to a PLC adds the connection options itself, with
``add_connection_options()``; the top-level parser has none. What the commands
share (connection options, password, JSON output, error reporting and exit
codes) is in ``_common``.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Protocol, Sequence

from ..error import S7Error
from . import browse, db_read, db_write, read, state, write
from ._common import (
    EPILOG,
    EXIT_FAILED,
    EXIT_INTERRUPTED,
    EXIT_USAGE,
    Subparsers,
    UsageError,
    check_connection_options,
    has_connection_options,
    library_logging,
    package_version,
    report_error,
    tolerate_unencodable_output,
)

__all__ = ["COMMANDS", "build_parser", "main"]


class Command(Protocol):
    """A command module: ``register()`` adds its subparser and sets its handler."""

    def register(self, subparsers: Subparsers) -> None: ...


#: The command modules, in the order ``--help`` lists them.
COMMANDS: tuple[Command, ...] = (browse, read, write, db_read, db_write, state)


def build_parser() -> argparse.ArgumentParser:
    """Build the ``s7commplus`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="s7commplus",
        description="Read and write Siemens S7-1200/1500 data over S7CommPlus.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version()}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="log the library's activity to stderr: -v for INFO, -vv for DEBUG with every protocol frame (see logging below)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for command in COMMANDS:
        command.register(subparsers)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the ``s7commplus`` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if has_connection_options(args):
        check_connection_options(parser, args)
    tolerate_unencodable_output()
    with library_logging(args.verbose):
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    """Run the command's handler and turn what it raises into an exit status."""
    try:
        return int(args.handler(args))
    except UsageError as exc:
        # A check made before connecting that argparse could not make.
        report_error(exc)
        return EXIT_USAGE
    except KeyError as exc:
        # An unknown tag name, which the client looks up before it sends the read or write.
        report_error(exc)
        return EXIT_USAGE
    except (S7Error, OSError, RuntimeError, ValueError) as exc:
        # OSError covers socket errors, ssl.SSLError (a failed handshake or
        # certificate verification, an unloadable certificate or key) and
        # unreadable files; RuntimeError is how the client reports a PLC that
        # rejected a read or write. Argument values are all checked before
        # connecting, so a ValueError here comes from the library: a response
        # it cannot parse, or a value it cannot encode for the tag's type.
        report_error(exc)
        return EXIT_FAILED
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
