"""Tests for the shareable real-PLC report wrapper."""

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from tests.real_plc import support
from tools.run_real_plc_acceptance import PASSWORD_ENV, marker_expression, redact_junit_hostname


def test_redact_junit_hostname_preserves_test_results(tmp_path: Path) -> None:
    report = tmp_path / "acceptance.junit.xml"
    report.write_text(
        '<testsuites><testsuite name="plc" hostname="tester-private-host" tests="1">'
        '<testcase name="connect"><failure message="expected">details</failure></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )

    redact_junit_hostname(report)

    assert b"tester-private-host" not in report.read_bytes()
    suite = ET.parse(report).getroot().find("testsuite")
    assert suite is not None
    assert suite.attrib == {"name": "plc", "hostname": "redacted", "tests": "1"}
    assert suite.find("testcase/failure").text == "details"


def _args(**overrides: bool) -> argparse.Namespace:
    values = {"allow_write": False, "allow_admin": False, "plc_use_tls": False, "include_pending": False}
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.mark.parametrize(
    ("overrides", "password", "expected"),
    [
        ({}, False, "(smoke) and not tls and not password and not pending"),
        ({"plc_use_tls": True}, True, "(smoke) and not pending"),
        (
            {"allow_write": True, "allow_admin": True, "plc_use_tls": True, "include_pending": True},
            True,
            "(smoke or write or administrative)",
        ),
        ({"allow_write": True}, False, "(smoke or write) and not tls and not password and not pending"),
    ],
)
def test_marker_expression_selects_only_runnable_scenarios(overrides: dict[str, bool], password: bool, expected: str) -> None:
    assert marker_expression(_args(**overrides), password) == expected


def test_runner_and_scenarios_read_the_same_password_variable() -> None:
    assert PASSWORD_ENV == support.PASSWORD_ENV
