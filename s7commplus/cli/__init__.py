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

Exit status: 0 on success; 1 when the operation fails (a connection, protocol,
TLS, certificate or authentication error, a certificate or key file that cannot
be loaded, or a PLC that rejects a read or write); 2 for a usage error (invalid
arguments or values, a missing certificate or key file, or an unknown tag);
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
    check_connection_options,
    has_connection_options,
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
    try:
        return int(args.handler(args))
    except (S7Error, OSError, RuntimeError) as exc:
        # OSError covers socket errors, ssl.SSLError (a failed handshake or
        # certificate verification, an unloadable certificate or key) and
        # unreadable files; RuntimeError is how the client reports a PLC that
        # rejected a read or write. ssl.SSLCertVerificationError is also a
        # ValueError, so this clause must come before the usage-error one.
        report_error(exc)
        return EXIT_FAILED
    except (KeyError, ValueError) as exc:
        report_error(exc)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
