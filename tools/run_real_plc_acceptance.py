#!/usr/bin/env python3
"""Run the safe S7CommPlus real-PLC profile and produce shareable artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


def redact_junit_hostname(path: Path) -> None:
    """Remove the tester machine name before the JUnit report is shared."""
    tree = ET.parse(path)
    for suite in tree.getroot().iter("testsuite"):
        if "hostname" in suite.attrib:
            suite.set("hostname", "redacted")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plc-ip", required=True, help="PLC address (used for connection only; never written to reports)")
    parser.add_argument("--tester", required=True, help="GitHub handle")
    parser.add_argument("--plc-family", required=True)
    parser.add_argument("--plc-model", required=True)
    parser.add_argument("--plc-firmware", required=True)
    parser.add_argument("--plc-order-code", default="")
    parser.add_argument("--plc-security-mode", required=True)
    parser.add_argument("--plc-tia-configuration", default="")
    parser.add_argument("--plc-port", type=int, default=102)
    parser.add_argument("--plc-rack", type=int, default=0)
    parser.add_argument("--plc-slot", type=int, default=1)
    parser.add_argument("--plc-db-read", type=int, default=1)
    parser.add_argument("--plc-db-write", type=int, default=2)
    parser.add_argument("--plc-use-tls", action="store_true", help="Enable TLS for S7CommPlus V2/V3 PLCs")
    parser.add_argument("--plc-tls-cert", type=Path, help="PEM client certificate")
    parser.add_argument("--plc-tls-key", type=Path, help="PEM client private key")
    parser.add_argument("--plc-tls-ca", type=Path, help="PEM CA certificate used to verify the PLC")
    parser.add_argument("--allow-write", action="store_true", help="Also run scratch writes with verified restoration")
    parser.add_argument("--allow-admin", action="store_true", help="Also run disruptive administrative scenarios")
    parser.add_argument("--output-dir", type=Path, default=Path("real-plc-results"))
    args = parser.parse_args()
    if bool(args.plc_tls_cert) != bool(args.plc_tls_key):
        parser.error("--plc-tls-cert and --plc-tls-key must be supplied together")
    if (args.plc_tls_cert or args.plc_tls_ca) and not args.plc_use_tls:
        parser.error("TLS certificate options require --plc-use-tls")
    return args


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"real-plc-s7commplus-{stamp}"
    junit = args.output_dir / f"{stem}.junit.xml"
    report = args.output_dir / f"{stem}.json"
    marker = "smoke"
    if args.allow_write:
        marker += " or write"
    if args.allow_admin:
        marker += " or administrative"
    pytest_args = [
        "tests/real_plc/test_acceptance.py",
        "--e2e",
        "-v",
        "--gherkin-terminal-reporter",
        "-m",
        marker,
        f"--junitxml={junit}",
        f"--plc-report-json={report}",
        f"--plc-ip={args.plc_ip}",
        f"--tester={args.tester}",
        f"--plc-family={args.plc_family}",
        f"--plc-model={args.plc_model}",
        f"--plc-firmware={args.plc_firmware}",
        f"--plc-order-code={args.plc_order_code}",
        f"--plc-security-mode={args.plc_security_mode}",
        f"--plc-tia-configuration={args.plc_tia_configuration}",
        f"--plc-port={args.plc_port}",
        f"--plc-rack={args.plc_rack}",
        f"--plc-slot={args.plc_slot}",
        f"--plc-db-read={args.plc_db_read}",
        f"--plc-db-write={args.plc_db_write}",
    ]
    if args.plc_use_tls:
        pytest_args.append("--plc-use-tls")
    for option, value in (
        ("--plc-tls-cert", args.plc_tls_cert),
        ("--plc-tls-key", args.plc_tls_key),
        ("--plc-tls-ca", args.plc_tls_ca),
    ):
        if value is not None:
            pytest_args.append(f"{option}={value}")
    if args.allow_write:
        pytest_args.append("--allow-plc-write")
    if args.allow_admin:
        pytest_args.append("--allow-plc-admin")
    result = pytest.main(pytest_args)
    if junit.exists():
        redact_junit_hostname(junit)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
