"""Unit tests for real-PLC safety and reporting helpers (no hardware needed)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.real_plc.reporting import RealPLCReport, sanitize_diagnostic
from tests.real_plc.support import PLCConfig, ScratchRestoreGuard, assert_canonical_fixture, canonical_fixture_bytes


def test_canonical_fixture_validates_all_documented_types() -> None:
    data = canonical_fixture_bytes()
    assert len(data) == 37
    assert_canonical_fixture(data)


@pytest.mark.parametrize("failure", [None, AssertionError("scenario failed"), KeyboardInterrupt()])
def test_scratch_guard_restores_after_success_failure_or_interrupt(failure: BaseException | None) -> None:
    original = b"\x12\x34"
    adapter = MagicMock()
    adapter.read.side_effect = [original, original]
    guard = ScratchRestoreGuard(adapter, 2, 0, 2)

    if failure is None:
        guard.restore()
    else:
        with pytest.raises(type(failure)):
            try:
                raise failure
            finally:
                guard.restore()

    adapter.write.assert_called_once_with(2, 0, original)


def test_scratch_guard_detects_failed_restoration() -> None:
    adapter = MagicMock()
    adapter.read.side_effect = [b"old", b"bad"]
    guard = ScratchRestoreGuard(adapter, 2, 0, 3)
    with pytest.raises(AssertionError, match="restoration verification failed"):
        guard.restore()


def test_report_sanitizes_network_credentials_and_certificate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tests.real_plc.reporting._git_source", lambda: {"kind": "git", "commit": "a" * 40, "dirty": False})
    report = RealPLCReport(sensitive_values=("plc.example.internal", "/private/client.pem"))
    fake = SimpleNamespace(
        when="call",
        passed=False,
        skipped=False,
        keywords={"smoke": 1, "real_plc": 1},
        longrepr=("connect 192.168.10.2 plc.example.internal password=hunter2 private_key=/tmp/key tls_cert=/private/client.pem"),
        nodeid="tests/real_plc/test_acceptance.py::test_failure",
        duration=0.1,
    )
    report.record(fake)
    target = tmp_path / "report.json"
    report.write(target, {"tester": "@tester", "model": "CPU 1511"})

    serialized = target.read_text()
    payload = json.loads(serialized)
    assert payload["schema_version"] == "1.0"
    assert payload["overall_result"] == "fail"
    for secret in ("192.168.10.2", "plc.example.internal", "hunter2", "/tmp/key", "/private/client.pem"):
        assert secret not in serialized


def test_sanitize_diagnostic_caps_size() -> None:
    assert len(sanitize_diagnostic("x" * 20, limit=5)) == 5


def _plc_config(**overrides: object) -> PLCConfig:
    values: dict[str, object] = dict(
        host="192.0.2.1",
        port=102,
        rack=0,
        slot=1,
        read_db=1,
        write_db=2,
        use_tls=True,
        tls_cert=None,
        tls_key=None,
        tls_ca=None,
    )
    values.update(overrides)
    return PLCConfig(**values)  # type: ignore[arg-type]


def test_umac_user_connects_without_the_password_then_authenticates() -> None:
    from tests.real_plc.support import S7CommPlusAdapter

    adapter = S7CommPlusAdapter(_plc_config(password="pw", username="tester"))
    adapter.client = MagicMock()
    adapter.connect()
    assert adapter.client.connect.call_args.kwargs["password"] is None
    adapter.client.authenticate.assert_called_once_with("pw", "tester")


def test_access_level_password_still_goes_to_connect() -> None:
    from tests.real_plc.support import S7CommPlusAdapter

    adapter = S7CommPlusAdapter(_plc_config(password="pw"))
    adapter.client = MagicMock()
    adapter.connect()
    assert adapter.client.connect.call_args.kwargs["password"] == "pw"
    adapter.client.authenticate.assert_not_called()


def test_async_umac_user_authenticates_after_connecting() -> None:
    from unittest.mock import AsyncMock

    from tests.real_plc.support import AsyncS7CommPlusAdapter

    adapter = AsyncS7CommPlusAdapter(_plc_config(password="pw", username="tester", client_kind="async"))
    adapter.client = AsyncMock()
    try:
        adapter.connect()
    finally:
        adapter.loop.close()
    assert adapter.client.connect.await_args.kwargs["password"] is None
    adapter.client.authenticate.assert_awaited_once_with("pw", "tester")


def test_a_short_user_name_is_redacted_only_as_a_whole_word() -> None:
    text = "login as ab failed; security mode: TLS, user tab, absent"
    assert sanitize_diagnostic(text, sensitive_words=("ab",)) == (
        "login as <redacted> failed; security mode: TLS, user tab, absent"
    )
