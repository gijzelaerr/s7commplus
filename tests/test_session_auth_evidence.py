"""Fixture provenance completeness, known answers and unified offline workflow."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7
from tools import verify_session_auth as workflow
from tools.transform7_reference import model
from tools.verify_session_auth_evidence import PROVENANCE, verify


def test_all_known_answer_evidence_is_manifested_and_unchanged() -> None:
    assert verify() == []


@pytest.mark.parametrize("number", [0, 1])
def test_complete_transform7_matches_pinned_upstream_known_answers(number: int) -> None:
    record = json.loads(PROVENANCE.read_text(encoding="utf-8"))["transform7_vectors"][number]
    fields = {key: bytes.fromhex(field["hex"]) for key, field in record["fields"].items()}
    destination = bytearray(72)
    transform7.execute(destination, bytearray(fields["prng1"]), bytearray(fields["prng2"]), fields["source"])
    assert destination == fields["destination"]
    result = model(fields["prng1"], fields["prng2"], fields["source"])
    assert result.destination == fields["destination"]


@pytest.mark.parametrize("mutation", ["hash", "missing", "source", "traversal", "vector", "duplicate", "revision"])
def test_bad_provenance_fails_closed(tmp_path: Path, mutation: str) -> None:
    document = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    if mutation == "hash":
        document["files"][0]["sha256"] = "0" * 64
    elif mutation == "missing":
        document["files"].pop()
    elif mutation == "source":
        document["files"][0]["upstream_source"] = "unrelated.bin"
    elif mutation == "traversal":
        document["files"][0]["path"] = "/etc/passwd"
    elif mutation == "vector":
        document["transform7_vectors"][0]["fields"]["destination"]["hex"] = "00" * 72
    elif mutation == "duplicate":
        document["transform7_vectors"][1] = document["transform7_vectors"][0]
    else:
        document["upstream_revision"] = "0" * 40
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert verify(path)


def test_workflow_default_is_offline_and_read_only() -> None:
    with patch.object(workflow.subprocess, "run", side_effect=AssertionError("subprocess not requested")):
        assert workflow.main([]) == 0


def test_workflow_reports_inventory_failure_without_running_more_checks() -> None:
    with patch.object(workflow, "artifacts", return_value=["drift"]), patch.object(workflow.subprocess, "run") as run:
        assert workflow.main(["--models"]) == 1
        run.assert_not_called()


def test_workflow_propagates_source_verifier_failure() -> None:
    with (
        patch.object(workflow, "evidence", return_value=[]),
        patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as run,
    ):
        assert workflow.main(["--upstream-root", "/synthetic/HarpoS7"]) == 7
        assert run.call_count == 1


def test_workflow_runs_all_requested_model_checks() -> None:
    with patch.object(workflow.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
        assert workflow.main(["--models"]) == 0
    assert len(run.call_args_list) == 7
    assert all(call.kwargs["check"] is False for call in run.call_args_list)
