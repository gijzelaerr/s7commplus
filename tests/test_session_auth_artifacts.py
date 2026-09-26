"""Tests for the authoritative SessionKey generated-artifact manifest."""

import json
from pathlib import Path

from tools.verify_session_auth_artifacts import DEFAULT_MANIFEST, verify


def _write_manifest(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def test_checked_in_artifacts_match_manifest() -> None:
    assert verify() == []


def test_changed_checksum_has_actionable_error(tmp_path: Path) -> None:
    document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    document["artifacts"][0]["sha256"] = "0" * 64
    manifest = tmp_path / "artifacts.json"
    _write_manifest(manifest, document)

    errors = verify(manifest)
    assert any("SHA-256 mismatch" in error for error in errors)


def test_missing_manifest_entry_is_reported(tmp_path: Path) -> None:
    document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    removed = document["artifacts"].pop()["path"]
    manifest = tmp_path / "artifacts.json"
    _write_manifest(manifest, document)

    errors = verify(manifest)
    assert f"unmanifested generated artifact: {removed}" in errors


def test_shared_data_loader_is_manifested(tmp_path: Path) -> None:
    document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    path = "s7commplus/session_auth/family0/_generated/data/__init__.py"
    document["artifacts"] = [record for record in document["artifacts"] if record["path"] != path]
    manifest = tmp_path / "artifacts.json"
    _write_manifest(manifest, document)
    assert f"unmanifested generated artifact: {path}" in verify(manifest)


def test_embedded_public_key_drift_and_missing_record_are_detected(tmp_path: Path) -> None:
    document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    first = document["embedded_public_keys"][0]
    first["sha256"] = "0" * 64
    removed = document["embedded_public_keys"].pop()["fingerprint"]
    manifest = tmp_path / "artifacts.json"
    _write_manifest(manifest, document)
    errors = verify(manifest)
    assert f"embedded public-key size/SHA-256 mismatch: {first['fingerprint']}" in errors
    assert f"unmanifested embedded public key: {removed}" in errors
