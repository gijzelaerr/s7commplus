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
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import math
import os
import struct
import sys
from typing import Any, Callable, Optional, Sequence

from .catalog import TagResult
from .client import S7CommPlusClient as Client
from .error import S7Error

_PASSWORD_ENV = "S7COMMPLUS_PASSWORD"

_EXIT_OK = 0
_EXIT_FAILED = 1
_EXIT_USAGE = 2
_EXIT_INTERRUPTED = 130

_EPILOG = f"""\
password:
  The PLC password is read from the {_PASSWORD_ENV} environment variable,
  or typed at the prompt --ask-password shows, which does not echo it.
  --password VALUE also works, but other users can see it in the process
  list and it stays in the shell history.

exit status:
  0    success
  1    the operation failed: connection, protocol, TLS, certificate or
       authentication error, a certificate or key file that cannot be
       loaded, or the PLC rejected a read or write
  2    usage error: invalid arguments or values, a missing certificate or
       key file, or an unknown tag
  130  interrupted
"""


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("s7commplus")
    except Exception:  # package metadata missing (running from a source tree)
        return "unknown"


def _parse_hex(value: str) -> bytes:
    """Parse ``"01 02"``/``"0102"``/``"0x01,0x02"`` into bytes for --hex options."""
    cleaned = value.replace("0x", "").replace("0X", "").replace(",", " ").replace(":", " ").replace("-", " ")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid hex bytes: {value!r}") from exc


def _int_in_range(what: str, low: int, high: int) -> Callable[[str], int]:
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


def _parse_real(text: str) -> float:
    """An argparse ``type`` accepting a value a 32-bit REAL can hold."""
    try:
        value = float(text)
        struct.pack(">f", value)  # OverflowError beyond the REAL range
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError(f"not a REAL (32-bit float) value: {text!r}") from None
    return value


def _existing_file(text: str) -> str:
    """An argparse ``type`` for a certificate or key path that must exist."""
    if not os.path.isfile(text):
        raise argparse.ArgumentTypeError(f"file not found: {text!r}")
    return text


def _connection_parser() -> argparse.ArgumentParser:
    """A reusable parent holding the connection options every command needs."""
    parser = argparse.ArgumentParser(add_help=False)
    group = parser.add_argument_group("connection")
    group.add_argument("--host", required=True, help="PLC IP address or hostname")
    group.add_argument("--port", type=_int_in_range("port", 1, 65535), default=102, help="TCP port (default: 102)")
    group.add_argument(
        "--tls",
        action="store_true",
        help="use TLS (S7CommPlus V2/V3); implied by --tls-ca, --tls-cert, --tls-key and --pin",
    )
    group.add_argument(
        "--tls-ca", type=_existing_file, metavar="PEM", help="CA certificate (PEM) that signed the PLC certificate"
    )
    group.add_argument("--tls-cert", type=_existing_file, metavar="PEM", help="client certificate (PEM); needs --tls-key")
    group.add_argument("--tls-key", type=_existing_file, metavar="PEM", help="client private key (PEM); needs --tls-cert")
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
        help=f"prompt for the PLC password without echoing it (overrides {_PASSWORD_ENV})",
    )
    group.add_argument(
        "--password",
        metavar="VALUE",
        help=f"PLC password; visible in the process list and shell history, prefer {_PASSWORD_ENV} or --ask-password",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Build the ``s7commplus`` argument parser."""
    formatting: dict[str, Any] = {"epilog": _EPILOG, "formatter_class": argparse.RawDescriptionHelpFormatter}
    parser = argparse.ArgumentParser(
        prog="s7commplus",
        description="Read and write Siemens S7-1200/1500 data over S7CommPlus.",
        **formatting,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    common = _connection_parser()

    browse = commands.add_parser("browse", parents=[common], help="list the PLC's symbolic tags", **formatting)
    browse.add_argument("--json", action="store_true", help="emit JSON")
    browse.set_defaults(handler=_cmd_browse)

    read = commands.add_parser("read", parents=[common], help="read one or more named tags", **formatting)
    read.add_argument("names", nargs="+", metavar="NAME")
    read.add_argument("--json", action="store_true", help="emit JSON (a NaN or infinite REAL/LREAL becomes null)")
    read.set_defaults(handler=_cmd_read)

    write = commands.add_parser("write", parents=[common], help="write one named tag", **formatting)
    write.add_argument("name", metavar="NAME")
    value = write.add_mutually_exclusive_group(required=True)
    value.add_argument("--hex", dest="hex_value", type=_parse_hex, metavar="BYTES", help="raw big-endian bytes")
    value.add_argument("--bool", dest="bool_value", type=int, choices=(0, 1), help="BOOL (1 byte)")
    value.add_argument("--int", dest="int_value", type=_int_in_range("INT", -(2**15), 2**15 - 1), help="INT (2 bytes)")
    value.add_argument("--dint", dest="dint_value", type=_int_in_range("DINT", -(2**31), 2**31 - 1), help="DINT (4 bytes)")
    value.add_argument("--real", dest="real_value", type=_parse_real, help="REAL (4 bytes)")
    value.add_argument("--string", dest="string_value", help="STRING/WSTRING text")
    write.set_defaults(handler=_cmd_write)

    db_number = _int_in_range("DB", 1, 0xFFFF)
    offset = _int_in_range("START", 0, 0xFFFFFFFF)

    db_read = commands.add_parser("db-read", parents=[common], help="read raw bytes from a DB", **formatting)
    db_read.add_argument("db", type=db_number, metavar="DB")
    db_read.add_argument("start", type=offset, metavar="START")
    db_read.add_argument("size", type=_int_in_range("SIZE", 1, 0xFFFFFFFF), metavar="SIZE")
    db_read.set_defaults(handler=_cmd_db_read)

    db_write = commands.add_parser("db-write", parents=[common], help="write raw bytes to a DB", **formatting)
    db_write.add_argument("db", type=db_number, metavar="DB")
    db_write.add_argument("start", type=offset, metavar="START")
    db_write.add_argument("--hex", dest="hex_value", type=_parse_hex, required=True, metavar="BYTES")
    db_write.set_defaults(handler=_cmd_db_write)

    state = commands.add_parser("state", parents=[common], help="read the CPU operating state (RUN/STOP)", **formatting)
    state.set_defaults(handler=_cmd_state)

    return parser


def _uses_tls(args: argparse.Namespace) -> bool:
    """``--tls`` itself, or any option that only makes sense with TLS."""
    return bool(args.tls or args.tls_ca or args.tls_cert or args.tls_key or args.tls_cert_fingerprint)


def _password(args: argparse.Namespace) -> Optional[str]:
    """The PLC password: ``--password``, else the ``--ask-password`` prompt, else the environment."""
    if args.password is not None:
        return str(args.password)
    if args.ask_password:
        try:
            return getpass.getpass("PLC password: ") or None
        except EOFError:
            raise ValueError("--ask-password: no password entered") from None
    return os.environ.get(_PASSWORD_ENV) or None


def _open(args: argparse.Namespace) -> Client:
    use_tls = _uses_tls(args)
    client = Client()
    client.connect(
        args.host,
        port=args.port,
        use_tls=use_tls,
        tls_ca=args.tls_ca,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_cert_fingerprint=args.tls_cert_fingerprint,
        password=args.password,
    )
    if use_tls:
        fingerprint = client.peer_certificate_fingerprint()
        if fingerprint is not None:
            print(f"TLS peer certificate SHA-256: {fingerprint.hex()}", file=sys.stderr)
    return client


def _json_safe(value: Any) -> Any:
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
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _print_json(payload: Any) -> None:
    """Write ``payload`` as strict JSON (no NaN or Infinity) to stdout."""
    sys.stdout.write(json.dumps(_json_safe(payload), indent=2, allow_nan=False) + "\n")


def _format_result(result: TagResult) -> str:
    if result.error is not None:
        return f"{result.tag.name} = <error: {result.error}>"
    assert result.value is not None
    decoded = result.tag.decode_value(result.value)
    if isinstance(decoded, bytes):
        return f"{result.tag.name} = {decoded.hex()}"
    return f"{result.tag.name} = {decoded}"


def _cmd_browse(args: argparse.Namespace) -> int:
    with _open(args) as client:
        tags = client.browse()
    if args.json:
        _print_json(tags)
        return _EXIT_OK
    for tag in tags:
        print(f"{tag.get('name', '')}\t{tag.get('data_type', '')}\t{tag.get('access_sequence', '')}")
    return _EXIT_OK


def _cmd_read(args: argparse.Namespace) -> int:
    with _open(args) as client:
        results = client.read_tags(list(args.names))
    if args.json:
        _print_json(
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
    return _EXIT_OK if all(result.success for result in results) else _EXIT_FAILED


def _cmd_write(args: argparse.Namespace) -> int:
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
    with _open(args) as client:
        client.write_tag(args.name, data)
    print(f"{args.name} = {data.hex()}")
    return _EXIT_OK


def _cmd_db_read(args: argparse.Namespace) -> int:
    with _open(args) as client:
        data = client.db_read(args.db, args.start, args.size)
    print(data.hex())
    return _EXIT_OK


def _cmd_db_write(args: argparse.Namespace) -> int:
    with _open(args) as client:
        client.db_write(args.db, args.start, args.hex_value)
    print(f"DB{args.db}[{args.start}:{args.start + len(args.hex_value)}] = {args.hex_value.hex()}")
    return _EXIT_OK


def _cmd_state(args: argparse.Namespace) -> int:
    with _open(args) as client:
        print(client.get_cpu_state())
    return _EXIT_OK


def _tolerate_unencodable_output() -> None:
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


def _report(exc: BaseException) -> None:
    # str(KeyError) adds quotes around the message; show the message itself.
    message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
    print(f"error: {message}", file=sys.stderr)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the ``s7commplus`` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.password is not None and args.ask_password:
        parser.error("--password and --ask-password cannot be used together")
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be given together")
    _tolerate_unencodable_output()
    try:
        args.password = _password(args)
        return int(args.handler(args))
    except (S7Error, OSError, RuntimeError) as exc:
        # OSError covers socket errors, ssl.SSLError (a failed handshake or
        # certificate verification, an unloadable certificate or key) and
        # unreadable files; RuntimeError is how the client reports a PLC that
        # rejected a read or write. ssl.SSLCertVerificationError is also a
        # ValueError, so this clause must come before the usage-error one.
        _report(exc)
        return _EXIT_FAILED
    except (KeyError, ValueError) as exc:
        _report(exc)
        return _EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return _EXIT_INTERRUPTED


if __name__ == "__main__":
    raise SystemExit(main())
