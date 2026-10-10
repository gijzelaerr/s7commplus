"""Sanitized, schema-versioned report generation for real-PLC runs."""

from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tests.real_plc.support import MetadataValue

SCHEMA_VERSION = "1.0"
# Scenario tags copied into reports; each is a marker registered in pyproject.toml.
_REPORTED_TAGS = (
    "administrative",
    "alarm",
    "cpu_state",
    "password",
    "pending",
    "real_plc",
    "smoke",
    "subscription",
    "symbolic",
    "tls",
    "write",
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|secret|private[_ -]?key|plc[_ -]?(?:ip|host)|tls[_ -]?(?:cert|key|ca))\s*[:=]\s*([^\s,;]+)"
)


def sanitize_diagnostic(value: object, sensitive_values: tuple[str, ...] = (), limit: int = 12_000) -> str:
    """Remove connection and credential material and cap report size."""
    text = str(value)
    for sensitive in sorted((item for item in sensitive_values if item), key=len, reverse=True):
        text = text.replace(sensitive, "<redacted>")
    text = _IPV4.sub("<redacted-ip>", text)
    text = _SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text[:limit]


def _git_source() -> dict[str, object]:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True, text=True).stdout)
        return {"kind": "git", "commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"kind": "installed", "version": importlib.metadata.version("s7commplus")}


@dataclass
class ScenarioResult:
    scenario_id: str
    status: str
    tags: list[str]
    duration_seconds: float
    diagnostic: str | None = None


@dataclass
class RealPLCReport:
    """Accumulate final pytest outcomes and emit the public-safe JSON format."""

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scenarios: dict[str, ScenarioResult] = field(default_factory=dict)
    runtime_metadata: dict[str, MetadataValue] = field(default_factory=dict)
    sensitive_values: tuple[str, ...] = ()

    def record(self, report: Any) -> None:
        nodeid = str(report.nodeid).replace("\\", "/")
        if "real_plc/test_acceptance.py::" not in nodeid:
            return
        if report.when == "call":
            status = "passed" if report.passed else "skipped" if report.skipped else "failed"
        elif report.when == "setup" and report.skipped:
            status = "skipped"
        else:
            return
        tags = sorted(tag for tag in _REPORTED_TAGS if tag in report.keywords)
        # The client a scenario ran with is one of its parameter ids (see --plc-client).
        parameters = nodeid.rsplit("[", 1)[1].rstrip("]").split("-") if nodeid.endswith("]") else []
        tags += sorted(kind for kind in ("sync", "async") if kind in parameters)
        diagnostic = None if report.passed else sanitize_diagnostic(report.longrepr, self.sensitive_values)
        self.scenarios[nodeid] = ScenarioResult(nodeid, status, tags, report.duration, diagnostic)

    def payload(self, supplied_metadata: dict[str, MetadataValue]) -> dict[str, object]:
        scenarios = [vars(result) for result in self.scenarios.values()]
        statuses = {result["status"] for result in scenarios}
        overall = "fail" if "failed" in statuses else "partial" if not scenarios or "skipped" in statuses else "pass"
        try:
            package_version = importlib.metadata.version("s7commplus")
        except importlib.metadata.PackageNotFoundError:
            package_version = "source-tree"
        return {
            "schema_version": SCHEMA_VERSION,
            "started_at": self.started_at.isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "overall_result": overall,
            "source": _git_source(),
            "environment": {
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "s7commplus": package_version,
                "pytest_bdd": importlib.metadata.version("pytest-bdd"),
            },
            "tester": supplied_metadata.pop("tester", ""),
            "plc": {**supplied_metadata, **self.runtime_metadata},
            "scenarios": scenarios,
        }

    def write(self, path: Path, supplied_metadata: dict[str, MetadataValue]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.payload(dict(supplied_metadata)), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def report_metadata(config: Any) -> dict[str, MetadataValue]:
    """Return only explicitly public-safe CLI metadata."""
    return {
        "tester": config.getoption("--tester"),
        "family": config.getoption("--plc-family"),
        "model": config.getoption("--plc-model"),
        "order_code": config.getoption("--plc-order-code"),
        "firmware": config.getoption("--plc-firmware"),
        "rack": config.getoption("--plc-rack"),
        "slot": config.getoption("--plc-slot"),
        "protocol_path": "s7commplus",
        "requested_tls": config.getoption("--plc-use-tls"),
        "tls_client_certificate": bool(config.getoption("--plc-tls-cert")),
        "tls_ca_verification": bool(config.getoption("--plc-tls-ca")),
        "security_mode": config.getoption("--plc-security-mode"),
        "tia_configuration": config.getoption("--plc-tia-configuration"),
    }
