"""``s7commplus state``: read the CPU operating state."""

from __future__ import annotations

import argparse

from ._common import EXIT_OK, Subparsers, add_command, open_client


def register(subparsers: Subparsers) -> None:
    """Add the ``state`` command."""
    parser = add_command(subparsers, "state", "read the CPU operating state (RUN/STOP)")
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    """Print ``RUN``, ``STOP`` or ``UNKNOWN``."""
    with open_client(args) as client:
        print(client.get_cpu_state())
    return EXIT_OK
