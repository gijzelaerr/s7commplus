"""Pieces the ``s7commplus`` commands share.

The connection options, the PLC password, JSON output, error reporting and the
exit codes. Each command module in this package builds its subparser with
:func:`add_command`. A command that talks to a PLC also calls
:func:`add_connection_options` and opens its connection with
:func:`open_client`; a command without a PLC leaves both out and needs no
``--host``.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import getpass
import json
import logging
import math
import os
import sys
from typing import Any, Callable, Iterator, Optional, TypeAlias

from ..client import S7CommPlusClient as Client

PASSWORD_ENV = "S7COMMPLUS_PASSWORD"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

#: What ``add_subparsers()`` returns; each command's ``register()`` takes it.
Subparsers: TypeAlias = "argparse._SubParsersAction[argparse.ArgumentParser]"

PASSWORD_HELP = f"""\
password:
  The PLC password is read from the {PASSWORD_ENV} environment variable,
  or typed at the prompt --ask-password shows, which does not echo it.
  --password VALUE also works, but other users can see it in the process
  list and it stays in the shell history.
"""

EXIT_STATUS_HELP = """\
exit status:
  0    success
  1    the operation failed: connection, protocol, TLS, certificate or
       authentication error, a certificate or key file that cannot be
       loaded, or the PLC rejected a read or write
  2    usage error: invalid arguments or values, a missing certificate or
       key file, or an unknown tag
  130  interrupted
"""

LOGGING_HELP = """\
logging:
  -v, given before the command, logs what the library does to stderr
  (INFO); -vv also logs every protocol frame in hex (DEBUG). DEBUG output
  holds the data read and written and the authentication exchange with
  the PLC: review it before you share it, and do not post it publicly as
  it is.
"""

#: The epilog of the top-level help. A command's help carries the exit status
#: and, when the command has the connection options, the password section.
EPILOG = f"{PASSWORD_HELP}\n{LOGGING_HELP}\n{EXIT_STATUS_HELP}"

#: The parent logger of every s7commplus module.
LIBRARY_LOGGER = "s7commplus"


def package_version() -> str:
    try:
        from importlib.metadata import version

        return version("s7commplus")
    except Exception:  # package metadata missing (running from a source tree)
        return "unknown"


def parse_hex(value: str) -> bytes:
    """Parse ``"01 02"``/``"0102"``/``"0x01,0x02"`` into bytes for --hex options."""
    cleaned = value.replace("0x", "").replace("0X", "").replace(",", " ").replace(":", " ").replace("-", " ")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid hex bytes: {value!r}") from exc


def int_in_range(what: str, low: int, high: int) -> Callable[[str], int]:
    """An argparse ``type`` accepting a decimal integer between ``low`` and ``high``."""

    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{what} must be between {low} and {high}, got {value}")
        return value

    return parse


#: argparse ``type`` functions for a DB number and a byte offset in a DB.
parse_db_number = int_in_range("DB", 1, 0xFFFF)
parse_db_start = int_in_range("START", 0, 0xFFFFFFFF)


def existing_file(text: str) -> str:
    """An argparse ``type`` for a certificate or key path that must exist."""
    if not os.path.isfile(text):
        raise argparse.ArgumentTypeError(f"file not found: {text!r}")
    return text


def add_command(subparsers: Subparsers, name: str, summary: str) -> argparse.ArgumentParser:
    """Add the subparser of command ``name``, with ``summary`` as its one-line help.

    The subparser has no connection options; a command that talks to a PLC adds
    them with :func:`add_connection_options`.
    """
    return subparsers.add_parser(
        name,
        help=summary,
        epilog=EXIT_STATUS_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def add_connection_options(parser: argparse.ArgumentParser) -> None:
    """Add ``--host`` (required), ``--port``, the TLS and the password options to ``parser``.

    Call it right after :func:`add_command`, before the command's own
    arguments, so that the usage line lists the connection options first. It
    also puts the password section into the command's help and marks the
    command, so that ``main()`` runs :func:`check_connection_options` for it.
    """
    group = parser.add_argument_group("connection")
    group.add_argument("--host", required=True, help="PLC IP address or hostname")
    group.add_argument("--port", type=int_in_range("port", 1, 65535), default=102, help="TCP port (default: 102)")
    group.add_argument(
        "--tls",
        action="store_true",
        help="use TLS (S7CommPlus V2/V3); implied by --tls-ca, --tls-cert, --tls-key and --pin",
    )
    group.add_argument("--tls-ca", type=existing_file, metavar="PEM", help="CA certificate (PEM) that signed the PLC certificate")
    group.add_argument("--tls-cert", type=existing_file, metavar="PEM", help="client certificate (PEM); needs --tls-key")
    group.add_argument("--tls-key", type=existing_file, metavar="PEM", help="client private key (PEM); needs --tls-cert")
    group.add_argument(
        "--tls-cert-fingerprint",
        "--pin",
        dest="tls_cert_fingerprint",
        metavar="SHA256",
        help="pin the PLC TLS certificate by its SHA-256 fingerprint (hex)",
    )
    group.add_argument(
        "--ask-password",
        action="store_true",
        help=f"prompt for the PLC password without echoing it (overrides {PASSWORD_ENV})",
    )
    group.add_argument(
        "--password",
        metavar="VALUE",
        help=f"PLC password; visible in the process list and shell history, prefer {PASSWORD_ENV} or --ask-password",
    )
    parser.set_defaults(connection_options=True)
    parser.epilog = f"{PASSWORD_HELP}\n{parser.epilog}" if parser.epilog else PASSWORD_HELP


def has_connection_options(args: argparse.Namespace) -> bool:
    """Whether the command ``args`` were parsed for has the connection options."""
    return bool(getattr(args, "connection_options", False))


def check_connection_options(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """The checks between connection options that argparse cannot express; a failure exits with 2."""
    if args.password is not None and args.ask_password:
        parser.error("--password and --ask-password cannot be used together")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be given together")


def uses_tls(args: argparse.Namespace) -> bool:
    """``--tls`` itself, or any option that only makes sense with TLS."""
    return bool(args.tls or args.tls_ca or args.tls_cert or args.tls_key or args.tls_cert_fingerprint)


def resolve_password(args: argparse.Namespace) -> Optional[str]:
    """The PLC password: ``--password``, else the ``--ask-password`` prompt, else the environment."""
    if args.password is not None:
        return str(args.password)
    if args.ask_password:
        try:
            return getpass.getpass("PLC password: ") or None
        except EOFError:
            raise ValueError("--ask-password: no password entered") from None
    return os.environ.get(PASSWORD_ENV) or None


def open_client(args: argparse.Namespace) -> Client:
    """Connect a client with the connection options in ``args``, asking for the password if needed."""
    password = resolve_password(args)
    use_tls = uses_tls(args)
    client = Client()
    client.connect(
        args.host,
        port=args.port,
        use_tls=use_tls,
        tls_ca=args.tls_ca,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_cert_fingerprint=args.tls_cert_fingerprint,
        password=password,
    )
    if use_tls:
        fingerprint = client.peer_certificate_fingerprint()
        if fingerprint is not None:
            print(f"TLS peer certificate SHA-256: {fingerprint.hex()}", file=sys.stderr)
    return client


def json_safe(value: Any) -> Any:
    """Make a decoded tag value or a browse entry strict-JSON serializable.

    Raw bytes become hex and NaN or infinite floats (which a REAL or LREAL can
    hold but JSON cannot) become ``null``; containers are converted element by
    element. Dates and times become ISO 8601 strings and durations seconds.
    """
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, float) and not math.isfinite(value):
        return None
    # SymbolicTag.decode_value() returns only bool, int, float, str and bytes
    # today, so the date, time and duration cases below are not reached yet.
    # They are kept so that --json keeps working once it also decodes DATE,
    # TIME_OF_DAY, DATE_AND_TIME/DTL and TIME values to these types.
    if isinstance(value, (datetime.date, datetime.time)):  # datetime is a date
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return value.total_seconds()
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return value


def print_json(payload: Any) -> None:
    """Write ``payload`` as strict JSON (no NaN or Infinity) to stdout."""
    sys.stdout.write(json.dumps(json_safe(payload), indent=2, allow_nan=False) + "\n")


def tolerate_unencodable_output() -> None:
    """Escape what the output encoding cannot show instead of failing the command.

    Redirected output on Windows uses the ANSI code page (cp1252), which cannot
    encode every character a PLC allows in a tag name; printing such a name
    raised UnicodeEncodeError half-way through ``browse``. Use ``--json`` for
    names that must survive exactly (it escapes non-ASCII).
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def report_error(exc: BaseException) -> None:
    """Print ``error: <message>`` to stderr."""
    # str(KeyError) adds quotes around the message; show the message itself.
    message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
    print(f"error: {message}", file=sys.stderr)


@contextlib.contextmanager
def library_logging(verbosity: int) -> Iterator[None]:
    """Send the library's log records to stderr while the command runs.

    ``verbosity`` is the ``-v`` count: 1 logs INFO and above, 2 or more also
    DEBUG, which includes every protocol frame in hex. 0 changes nothing, so
    the library stays as quiet as it is without the command line. Afterwards
    the handler is removed and the logger's level restored, so calling
    ``main()`` leaves no logging configuration behind.
    """
    if verbosity <= 0:
        yield
        return
    level = logging.INFO if verbosity == 1 else logging.DEBUG
    logger = logging.getLogger(LIBRARY_LOGGER)
    handler = logging.StreamHandler(sys.stderr)
    # The handler filters too: a module's logger may have a lower level of its own.
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    previous_level = logger.level
    logger.setLevel(level)
    logger.addHandler(handler)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
