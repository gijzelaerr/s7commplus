"""Tests for the shareable real-PLC report wrapper."""

from pathlib import Path
import xml.etree.ElementTree as ET

from tools.run_real_plc_acceptance import redact_junit_hostname


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
