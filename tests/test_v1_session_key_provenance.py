"""The HarpoS7 public keys and upstream known-answer fixtures match their pinned provenance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import verify_v1_session_key as provenance


def _write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_checked_in_keys_and_fixtures_match_their_provenance() -> None:
    assert provenance.verify_public_keys() == []
    assert provenance.verify_fixtures() == []
    assert provenance.main([]) == 0


def test_every_embedded_key_is_manifested() -> None:
    document = json.loads(provenance.PUBLIC_KEYS.read_text(encoding="utf-8"))
    assert {record["fingerprint"] for record in document["embedded_public_keys"]} == set(provenance.embedded_keys())


def test_changed_key_and_missing_record_are_detected(tmp_path: Path) -> None:
    document = json.loads(provenance.PUBLIC_KEYS.read_text(encoding="utf-8"))
    first = document["embedded_public_keys"][0]
    first["sha256"] = "0" * 64
    removed = document["embedded_public_keys"].pop()["fingerprint"]
    errors = provenance.verify_public_keys(_write(tmp_path / "public_keys.json", document))
    assert f"embedded public-key size/SHA-256 mismatch: {first['fingerprint']}" in errors
    assert f"unmanifested embedded public key: {removed}" in errors


def test_key_source_mismatch_is_detected(tmp_path: Path) -> None:
    document = json.loads(provenance.PUBLIC_KEYS.read_text(encoding="utf-8"))
    first = document["embedded_public_keys"][0]
    first["upstream_source"] = "HarpoS7.PublicKeys/Keys/elsewhere.bin"
    errors = provenance.verify_public_keys(_write(tmp_path / "public_keys.json", document))
    assert errors == [f"embedded public-key source mismatch: {first['fingerprint']}"]


@pytest.mark.parametrize("mutation", ["hash", "missing", "source", "traversal", "vector", "duplicate", "revision"])
def test_bad_fixture_provenance_fails_closed(tmp_path: Path, mutation: str) -> None:
    document = json.loads(provenance.PROVENANCE.read_text(encoding="utf-8"))
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
    assert provenance.verify_fixtures(_write(tmp_path / "provenance.json", document))


def _upstream_checkout(root: Path) -> None:
    """The upstream files the fixtures and keys name, as a HarpoS7 checkout holds them."""
    document = json.loads(provenance.PROVENANCE.read_text(encoding="utf-8"))
    for record in document["files"]:
        target = root / record["upstream_source"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((provenance.REPOSITORY_ROOT / record["path"]).read_bytes())
    for vector in document["transform7_vectors"]:
        for field in vector["fields"].values():
            target = root / field["upstream_source"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes.fromhex(field["hex"]))
    keys = provenance.embedded_keys()
    for record in json.loads(provenance.PUBLIC_KEYS.read_text(encoding="utf-8"))["embedded_public_keys"]:
        target = root / record["upstream_source"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(keys[record["fingerprint"]])


def test_upstream_checkout_comparison(tmp_path: Path) -> None:
    _upstream_checkout(tmp_path)
    assert provenance.main(["--upstream-root", str(tmp_path)]) == 0
    changed = tmp_path / "HarpoS7.Family0.Tests/Blobs/Transforms/transform1-src.bin"
    changed.write_bytes(bytes(len(changed.read_bytes())))
    errors = provenance.verify_fixtures(upstream_root=tmp_path)
    assert errors == ["upstream bytes differ: tests/fixtures/family0/transforms/transform1-src.bin"]
    (tmp_path / "HarpoS7.PublicKeys").rename(tmp_path / "moved")
    assert any(
        error.startswith("cannot read upstream file for ") for error in provenance.verify_public_keys(upstream_root=tmp_path)
    )
