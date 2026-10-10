"""Dry run of every real-PLC Gherkin scenario against in-memory fake clients.

Without ``--e2e`` the acceptance scenarios are all skipped, so a step without a
binding, or step code that no longer matches the client API, would first show
up on a volunteer's PLC. This runs them in a subprocess with the
``tests.real_plc.fake_plc`` plugin, for both clients and with every opt-in
enabled, and checks the sanitized report. It selects the scenarios with the
runner's own marker expression, so a scenario the runner could never select
fails here too.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.real_plc.support import PASSWORD_ENV
from tools.run_real_plc_acceptance import marker_expression

ROOT = Path(__file__).resolve().parents[1]
DRY_RUN_PASSWORD = "dry-run-password-7f3a"


@pytest.fixture(scope="module")
def dry_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[subprocess.CompletedProcess[str], dict[str, object], str]:
    everything = argparse.Namespace(allow_write=True, allow_admin=True, plc_use_tls=True, include_pending=True)
    output = tmp_path_factory.mktemp("real-plc-dry-run")
    report = output / "report.json"
    junit = output / "report.junit.xml"
    env = {**os.environ, PASSWORD_ENV: DRY_RUN_PASSWORD}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/real_plc/test_acceptance.py",
            "-p",
            "tests.real_plc.fake_plc",
            "-p",
            "no:cacheprovider",
            "-m",
            marker_expression(everything, password_configured=True),
            "--e2e",
            "--allow-plc-write",
            "--allow-plc-admin",
            "--plc-use-tls",
            "--plc-client=both",
            "--plc-expected-cpu-state=RUN",
            "--plc-ip=192.0.2.10",
            f"--plc-report-json={report}",
            f"--junitxml={junit}",
            "-q",
            "-rs",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    payload = json.loads(report.read_text(encoding="utf-8")) if report.exists() else {}
    artifacts = (report.read_text(encoding="utf-8") if report.exists() else "") + (
        junit.read_text(encoding="utf-8") if junit.exists() else ""
    )
    return result, payload, artifacts


def test_every_scenario_passes_against_the_fake_plc(
    dry_run: tuple[subprocess.CompletedProcess[str], dict[str, object], str],
) -> None:
    result, payload, _ = dry_run
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    assert payload["overall_result"] == "pass"
    scenarios = payload["scenarios"]
    assert isinstance(scenarios, list)
    assert {scenario["status"] for scenario in scenarios} == {"passed"}


def test_the_runner_can_select_every_scenario(
    dry_run: tuple[subprocess.CompletedProcess[str], dict[str, object], str],
) -> None:
    _, payload, _ = dry_run
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/real_plc/test_acceptance.py", "--plc-client=both", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    every_case = [line for line in collected.stdout.splitlines() if "::" in line]
    scenarios = payload["scenarios"]
    assert isinstance(scenarios, list)
    assert every_case and len(scenarios) == len(every_case)


def test_every_scenario_runs_with_both_clients(
    dry_run: tuple[subprocess.CompletedProcess[str], dict[str, object], str],
) -> None:
    _, payload, _ = dry_run
    scenarios = payload["scenarios"]
    assert isinstance(scenarios, list)
    sync = {scenario["scenario_id"].replace("sync", "<client>") for scenario in scenarios if "sync" in scenario["tags"]}
    asynchronous = {scenario["scenario_id"].replace("async", "<client>") for scenario in scenarios if "async" in scenario["tags"]}
    assert sync and sync == asynchronous


def test_reports_contain_neither_the_password_nor_the_address(
    dry_run: tuple[subprocess.CompletedProcess[str], dict[str, object], str],
) -> None:
    _, _, artifacts = dry_run
    assert DRY_RUN_PASSWORD not in artifacts
    assert "192.0.2.10" not in artifacts
