"""Command-line interface tests."""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import ssl
import struct
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from s7commplus.catalog import SymbolicTag, TagResult
from s7commplus.cli import COMMANDS, browse, build_parser, db_read, db_write, main, read, state, write
from s7commplus.cli._common import json_safe, parse_hex
from s7commplus.protocol import ProtocolVersion
from s7commplus.server import S7CommPlusServer
from tests.conftest import get_free_tcp_port
from tests.test_s7_tls import _generate_self_signed_cert

_BROWSE_ITEM = {
    "name": "DB1.Motor.Speed",
    "access_sequence": "8A0E0001.A.2",
    "data_type": "REAL",
    "symbol_crc": 0,
    "array_dimensions": (),
    "string_length": 0,
    "opt_address": 0,
    "opt_bitoffset": 0,
    "nonopt_address": 0,
    "nonopt_bitoffset": 0,
}

_SECRET = "s3cret-Pa55"


class _FakeClient:
    """A Client stand-in covering the surface the CLI uses."""

    def __init__(self) -> None:
        self.writes: dict[str, bytes] = {}
        self.db_writes: list[tuple[int, int, bytes]] = []
        self.connected = False
        self.connect_kwargs: dict[str, Any] = {}
        self.real_value = 1.5

    def connect(self, *args: Any, **kwargs: Any) -> None:
        self.connected = True
        self.connect_kwargs = kwargs

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *args: Any) -> bool:
        self.connected = False
        return False

    def browse(self) -> list[dict[str, Any]]:
        return [dict(_BROWSE_ITEM)]

    def read_tags(self, names: list[str]) -> list[TagResult]:
        tag = SymbolicTag.from_browse(dict(_BROWSE_ITEM))
        return [TagResult(tag=tag, value=struct.pack(">f", self.real_value)) for _ in names]

    def write_tag(self, name: str, data: bytes) -> None:
        self.writes[name] = data

    def db_read(self, db: int, start: int, size: int) -> bytes:
        return bytes.fromhex("0102030405060708")[:size]

    def db_write(self, db: int, start: int, data: bytes) -> None:
        self.db_writes.append((db, start, data))

    def get_cpu_state(self) -> str:
        return "RUN"

    def peer_certificate_fingerprint(self) -> bytes:
        return bytes.fromhex("ab" * 32)


@pytest.fixture()
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr("s7commplus.cli._common.Client", lambda: client)
    monkeypatch.delenv("S7COMMPLUS_PASSWORD", raising=False)
    return client


@pytest.fixture()
def emulator() -> Generator[tuple[S7CommPlusServer, int], None, None]:
    srv = S7CommPlusServer()
    srv.register_raw_db(1, bytearray(16))
    port = get_free_tcp_port()
    srv.start(port=port)
    time.sleep(0.1)
    yield srv, port
    srv.stop()


@pytest.fixture()
def tls_emulator() -> Generator[tuple[int, str], None, None]:
    """A V2 TLS emulator on a free port, with its self-signed certificate."""
    cert_path, key_path = _generate_self_signed_cert()
    srv = S7CommPlusServer(protocol_version=ProtocolVersion.V2)
    srv.register_raw_db(1, bytearray(16))
    port = get_free_tcp_port()
    srv.start(port=port, use_tls=True, tls_cert=cert_path, tls_key=key_path)
    time.sleep(0.1)
    yield port, cert_path
    srv.stop()
    os.unlink(cert_path)
    os.unlink(key_path)


def _exit_code(argv: list[str]) -> Any:
    """Run main() where argparse is expected to reject argv; return its exit code."""
    with pytest.raises(SystemExit) as exc_info:
        main(argv)
    return exc_info.value.code


def _strict_json(text: str) -> Any:
    """json.loads that refuses the NaN/Infinity extensions Python accepts by default."""

    def refuse(constant: str) -> None:
        raise ValueError(f"not valid JSON: {constant}")

    return json.loads(text, parse_constant=refuse)


def test_parse_hex_accepts_common_separators() -> None:
    assert parse_hex("01 02 03") == b"\x01\x02\x03"
    assert parse_hex("010203") == b"\x01\x02\x03"
    assert parse_hex("0x01,0x02,0x03") == b"\x01\x02\x03"
    assert parse_hex("01:02-03") == b"\x01\x02\x03"


def test_parse_hex_rejects_garbage() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_hex("zz")


def test_parser_requires_a_host() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["browse"])


def test_write_requires_a_value() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["write", "--host", "plc", "DB1.x"])


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["browse", "--host", "plc"])
    assert args.command == "browse"
    assert args.host == "plc"
    assert args.port == 102
    assert args.tls is False
    assert args.password is None
    assert args.ask_password is False
    assert args.handler is browse.run


def test_commands_lists_the_command_modules_in_help_order() -> None:
    assert COMMANDS == (browse, read, write, db_read, db_write, state)


@pytest.mark.parametrize(
    ("module", "argv"),
    [
        (browse, ["browse"]),
        (read, ["read", "DB1.x"]),
        (write, ["write", "DB1.x", "--int", "1"]),
        (db_read, ["db-read", "1", "0", "4"]),
        (db_write, ["db-write", "1", "0", "--hex", "00"]),
        (state, ["state"]),
    ],
)
def test_register_adds_the_command_and_its_handler(module: Any, argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="test")
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)
    assert list(subparsers.choices) == [argv[0]]
    args = parser.parse_args([*argv, "--host", "plc"])
    assert args.command == argv[0]
    assert args.handler is module.run


def test_runs_as_python_m_s7commplus_cli() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "s7commplus.cli", "--help"], cwd=root, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("usage: s7commplus ")


def test_pin_is_an_alias_for_tls_cert_fingerprint() -> None:
    args = build_parser().parse_args(["state", "--host", "plc", "--pin", "aabb"])
    assert args.tls_cert_fingerprint == "aabb"


def test_cli_prints_the_fingerprint_when_tls(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["state", "--host", "plc", "--tls"]) == 0
    assert "ab" * 32 in capsys.readouterr().err


def test_help_documents_exit_status_and_password_sources() -> None:
    top = build_parser().format_help()
    assert "exit status:" in top
    for code in ("0", "1", "2", "130"):
        assert f"\n  {code} " in top
    assert "S7COMMPLUS_PASSWORD" in top


def test_subcommand_help_carries_the_epilog(capsys: pytest.CaptureFixture[str]) -> None:
    assert _exit_code(["read", "--help"]) == 0
    out = capsys.readouterr().out
    assert "exit status:" in out
    assert "--ask-password" in out
    assert "implied by" in out


def test_cli_browse(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["browse", "--host", "plc"]) == 0
    out = capsys.readouterr().out
    assert "DB1.Motor.Speed" in out
    assert "REAL" in out


def test_cli_browse_survives_a_name_the_output_encoding_cannot_show(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PLCSIM's test project has a DB name with U+009F, which cp1252 (redirected
    # output on Windows) cannot encode; browse used to stop there with exit code 2.
    item = dict(_BROWSE_ITEM, name="DB3 odd\x9fname.x")
    monkeypatch.setattr(fake_client, "browse", lambda: [item])
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    assert main(["browse", "--host", "plc"]) == 0
    sys.stdout.flush()
    assert raw.getvalue().decode("cp1252").startswith("DB3 odd\\x9fname.x\tREAL\t")


def test_cli_browse_json(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["browse", "--host", "plc", "--json"]) == 0
    payload = _strict_json(capsys.readouterr().out)
    assert payload[0]["name"] == "DB1.Motor.Speed"
    assert payload[0]["array_dimensions"] == []


def test_cli_browse_json_converts_entries_like_read(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    item = dict(_BROWSE_ITEM, raw=b"\x01\xff", scale=float("nan"))
    monkeypatch.setattr(fake_client, "browse", lambda: [item])
    assert main(["browse", "--host", "plc", "--json"]) == 0
    payload = _strict_json(capsys.readouterr().out)
    assert payload[0]["raw"] == "01ff"
    assert payload[0]["scale"] is None


def test_cli_read_decodes_a_scalar(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["read", "--host", "plc", "DB1.Motor.Speed"]) == 0
    assert "DB1.Motor.Speed = 1.5" in capsys.readouterr().out


def test_cli_read_json(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["read", "--host", "plc", "DB1.Motor.Speed", "--json"]) == 0
    payload = _strict_json(capsys.readouterr().out)
    assert payload == [{"name": "DB1.Motor.Speed", "value": 1.5, "error": None}]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_cli_read_json_emits_null_for_a_real_json_cannot_hold(
    fake_client: _FakeClient, value: float, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_client.real_value = value
    assert main(["read", "--host", "plc", "DB1.Motor.Speed", "--json"]) == 0
    payload = _strict_json(capsys.readouterr().out)
    assert payload == [{"name": "DB1.Motor.Speed", "value": None, "error": None}]


@pytest.mark.parametrize(
    ("flag", "value", "expected"),
    [
        ("--hex", "0102", b"\x01\x02"),
        ("--bool", "1", b"\x01"),
        ("--int", "258", struct.pack(">h", 258)),
        ("--int", "-32768", struct.pack(">h", -32768)),
        ("--dint", "70000", struct.pack(">i", 70000)),
        ("--dint", "2147483647", struct.pack(">i", 2147483647)),
        ("--real", "1.5", struct.pack(">f", 1.5)),
        ("--real", "3.4e38", struct.pack(">f", 3.4e38)),
        ("--string", "hi", b"hi"),
    ],
)
def test_cli_write_encodes_the_value(
    fake_client: _FakeClient, flag: str, value: str, expected: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["write", "--host", "plc", "DB1.Motor.Speed", flag, value]) == 0
    assert fake_client.writes["DB1.Motor.Speed"] == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["write", "DB1.x", "--int", "40000"],
        ["write", "DB1.x", "--int", "-32769"],
        ["write", "DB1.x", "--int", "1.5"],
        ["write", "DB1.x", "--dint", "2147483648"],
        ["write", "DB1.x", "--real", "1e39"],
        ["write", "DB1.x", "--real", "abc"],
        ["db-read", "70000", "0", "4"],
        ["db-read", "0", "0", "4"],
        ["db-read", "1", "-1", "4"],
        ["db-read", "1", "0", "0"],
        ["db-write", "1", "4294967296", "--hex", "00"],
        ["state", "--port", "70000"],
    ],
)
def test_cli_rejects_an_out_of_range_value_as_a_usage_error(
    fake_client: _FakeClient, argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _exit_code([*argv, "--host", "plc"]) == 2
    assert "error:" in capsys.readouterr().err
    assert not fake_client.connected
    assert fake_client.writes == {}
    assert fake_client.db_writes == []


def test_cli_write_rejected_by_the_plc_exits_1(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def reject(name: str, data: bytes) -> None:
        raise RuntimeError(f"Symbolic write failed for {name!r}: PLC error 0x1234")

    monkeypatch.setattr(fake_client, "write_tag", reject)
    assert main(["write", "--host", "plc", "DB1.Motor.Speed", "--real", "1.5"]) == 1
    assert "error: Symbolic write failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure"),
        ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"),
        PermissionError(13, "Permission denied", "plc.key"),
        ConnectionResetError(104, "Connection reset by peer"),
    ],
)
def test_cli_connect_os_and_tls_errors_exit_1(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, error: OSError, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: Any, **kwargs: Any) -> None:
        raise error

    monkeypatch.setattr(fake_client, "connect", fail)
    assert main(["state", "--host", "plc", "--tls"]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_read_reports_unknown_tag(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class _Unknown(_FakeClient):
        def read_tags(self, names: list[str]) -> list[TagResult]:
            raise KeyError(f"Unknown symbolic tag: {names[0]!r}")

    monkeypatch.setattr("s7commplus.cli._common.Client", lambda: _Unknown())
    assert main(["read", "--host", "plc", "DB1.nope"]) == 2
    assert capsys.readouterr().err.strip() == "error: Unknown symbolic tag: 'DB1.nope'"


def test_cli_db_read_bytes(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["db-read", "--host", "plc", "1", "0", "4"]) == 0
    assert capsys.readouterr().out.strip() == "01020304"


def test_cli_db_write_bytes(fake_client: _FakeClient) -> None:
    assert main(["db-write", "--host", "plc", "1", "2", "--hex", "aabb"]) == 0
    assert fake_client.db_writes == [(1, 2, b"\xaa\xbb")]


def test_cli_state(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["state", "--host", "plc"]) == 0
    assert capsys.readouterr().out.strip() == "RUN"
    assert fake_client.connect_kwargs["use_tls"] is False
    assert fake_client.connect_kwargs["password"] is None


def test_cli_password_option_is_passed_through(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["state", "--host", "plc", "--password", _SECRET]) == 0
    assert fake_client.connect_kwargs["password"] == _SECRET
    captured = capsys.readouterr()
    assert _SECRET not in captured.out + captured.err


def test_cli_password_from_the_environment(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("S7COMMPLUS_PASSWORD", _SECRET)
    assert main(["state", "--host", "plc"]) == 0
    assert fake_client.connect_kwargs["password"] == _SECRET
    captured = capsys.readouterr()
    assert _SECRET not in captured.out + captured.err


def test_cli_empty_password_variable_means_no_password(fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S7COMMPLUS_PASSWORD", "")
    assert main(["state", "--host", "plc"]) == 0
    assert fake_client.connect_kwargs["password"] is None


def test_cli_password_option_overrides_the_environment(fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S7COMMPLUS_PASSWORD", "from-env")
    assert main(["state", "--host", "plc", "--password", _SECRET]) == 0
    assert fake_client.connect_kwargs["password"] == _SECRET


def test_cli_ask_password_prompts_without_echo(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str = "Password: ", stream: Any = None) -> str:
        prompts.append(prompt)
        return _SECRET

    monkeypatch.setenv("S7COMMPLUS_PASSWORD", "from-env")
    monkeypatch.setattr("s7commplus.cli._common.getpass.getpass", fake_getpass)
    assert main(["state", "--host", "plc", "--ask-password"]) == 0
    assert prompts == ["PLC password: "]
    assert fake_client.connect_kwargs["password"] == _SECRET
    captured = capsys.readouterr()
    assert _SECRET not in captured.out + captured.err


def test_cli_ask_password_without_input_is_a_usage_error(
    fake_client: _FakeClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_input(prompt: str = "Password: ", stream: Any = None) -> str:
        raise EOFError

    monkeypatch.setattr("s7commplus.cli._common.getpass.getpass", no_input)
    assert main(["state", "--host", "plc", "--ask-password"]) == 2
    assert "error:" in capsys.readouterr().err
    assert not fake_client.connected


def test_cli_password_and_ask_password_are_exclusive(fake_client: _FakeClient) -> None:
    assert _exit_code(["state", "--host", "plc", "--password", "x", "--ask-password"]) == 2


def test_cli_pin_implies_tls(fake_client: _FakeClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["state", "--host", "plc", "--pin", "ab" * 32]) == 0
    assert fake_client.connect_kwargs["use_tls"] is True
    assert fake_client.connect_kwargs["tls_cert_fingerprint"] == "ab" * 32
    assert "ab" * 32 in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--tls-ca", "--tls-cert-fingerprint"])
def test_cli_tls_options_imply_tls(fake_client: _FakeClient, tmp_path: Path, option: str) -> None:
    value = "ab" * 32
    if option == "--tls-ca":
        value = str(tmp_path / "ca.pem")
        Path(value).write_bytes(b"")
    assert main(["state", "--host", "plc", option, value]) == 0
    assert fake_client.connect_kwargs["use_tls"] is True


def test_cli_client_certificate_and_key_imply_tls(fake_client: _FakeClient, tmp_path: Path) -> None:
    cert, key = tmp_path / "client.pem", tmp_path / "client.key"
    cert.write_bytes(b"")
    key.write_bytes(b"")
    assert main(["state", "--host", "plc", "--tls-cert", str(cert), "--tls-key", str(key)]) == 0
    assert fake_client.connect_kwargs["use_tls"] is True
    assert fake_client.connect_kwargs["tls_cert"] == str(cert)
    assert fake_client.connect_kwargs["tls_key"] == str(key)


@pytest.mark.parametrize("option", ["--tls-cert", "--tls-key"])
def test_cli_client_certificate_needs_its_key(
    fake_client: _FakeClient, tmp_path: Path, option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "client.pem"
    path.write_bytes(b"")
    assert _exit_code(["state", "--host", "plc", option, str(path)]) == 2
    assert "--tls-cert and --tls-key" in capsys.readouterr().err
    assert not fake_client.connected


@pytest.mark.parametrize("option", ["--tls-ca", "--tls-cert", "--tls-key"])
def test_cli_missing_certificate_file_is_a_usage_error(
    fake_client: _FakeClient, tmp_path: Path, option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = str(tmp_path / "missing.pem")
    assert _exit_code(["state", "--host", "plc", option, missing]) == 2
    assert "file not found" in capsys.readouterr().err
    assert not fake_client.connected


def test_cli_db_read_end_to_end(emulator: tuple[S7CommPlusServer, int], capsys: pytest.CaptureFixture[str]) -> None:
    _srv, port = emulator
    assert main(["db-read", "--host", "127.0.0.1", "--port", str(port), "1", "0", "4"]) == 0
    assert len(capsys.readouterr().out.strip()) == 8


def test_cli_db_write_end_to_end(emulator: tuple[S7CommPlusServer, int], capsys: pytest.CaptureFixture[str]) -> None:
    _srv, port = emulator
    assert main(["db-write", "--host", "127.0.0.1", "--port", str(port), "1", "0", "--hex", "deadbeef"]) == 0
    capsys.readouterr()
    assert main(["db-read", "--host", "127.0.0.1", "--port", str(port), "1", "0", "4"]) == 0
    assert capsys.readouterr().out.strip() == "deadbeef"


def test_cli_tls_end_to_end_with_the_plc_ca(tls_emulator: tuple[int, str], capsys: pytest.CaptureFixture[str]) -> None:
    port, cert_path = tls_emulator
    # --tls-ca alone switches TLS on.
    assert main(["db-read", "--host", "127.0.0.1", "--port", str(port), "--tls-ca", cert_path, "1", "0", "4"]) == 0
    assert capsys.readouterr().out.strip() == "00000000"


def test_cli_tls_certificate_verification_failure_exits_1(
    tls_emulator: tuple[int, str], capsys: pytest.CaptureFixture[str]
) -> None:
    port, _cert_path = tls_emulator
    other_ca, other_key = _generate_self_signed_cert()
    try:
        assert main(["state", "--host", "127.0.0.1", "--port", str(port), "--tls", "--tls-ca", other_ca]) == 1
    finally:
        os.unlink(other_ca)
        os.unlink(other_key)
    # The raw ssl error, or S7CertificateError once the client maps it: both name the reason,
    # which OpenSSL 1.1 spells "self signed certificate" and OpenSSL 3 "self-signed certificate".
    assert "self signed certificate" in capsys.readouterr().err.replace("-", " ")


def test_cli_unloadable_ca_file_exits_1(
    tls_emulator: tuple[int, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    port, _cert_path = tls_emulator
    garbage = tmp_path / "not-a-certificate.pem"
    garbage.write_bytes(b"not a certificate\n")
    assert main(["state", "--host", "127.0.0.1", "--port", str(port), "--tls", "--tls-ca", str(garbage)]) == 1
    assert "error:" in capsys.readouterr().err


def test_json_safe_converts_bytes_non_finite_floats_and_containers() -> None:
    value = {
        "raw": b"\x01\xff",
        "nan": float("nan"),
        "inf": float("-inf"),
        "real": 1.5,
        "flag": True,
        "arr": (1, [float("inf"), "x"]),
    }
    assert _strict_json(json.dumps(json_safe(value), allow_nan=False)) == {
        "raw": "01ff",
        "nan": None,
        "inf": None,
        "real": 1.5,
        "flag": True,
        "arr": [1, [None, "x"]],
    }


def test_json_safe_converts_dates_times_and_durations() -> None:
    # decode_value() does not return these types yet; built directly here.
    value = {
        "d": datetime.date(2026, 10, 2),
        "t": datetime.time(12, 34, 56),
        "dt": datetime.datetime(2026, 10, 8, 7, 48, 1, 250000),
        "span": datetime.timedelta(milliseconds=1500),
        "arr": (1, [datetime.date(1990, 1, 1)]),
    }
    assert json.loads(json.dumps(json_safe(value))) == {
        "d": "2026-10-02",
        "t": "12:34:56",
        "dt": "2026-10-08T07:48:01.250000",
        "span": 1.5,
        "arr": [1, ["1990-01-01"]],
    }


def test_cli_connection_error_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    port = get_free_tcp_port()  # nothing listens here
    assert main(["db-read", "--host", "127.0.0.1", "--port", str(port), "1", "0", "4"]) == 1
    assert "error:" in capsys.readouterr().err
