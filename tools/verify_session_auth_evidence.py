"""Verify immutable upstream known-answer provenance, not PLC-capture claims."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.verify_session_auth_artifacts import DEFAULT_MANIFEST, REPOSITORY_ROOT

FIXTURE_ROOT = REPOSITORY_ROOT / "tests/fixtures/family0"
PROVENANCE = FIXTURE_ROOT / "provenance.json"
CATEGORIES = {"bit_operations": "BitOperations", "monoliths": "Monoliths", "transforms": "Transforms"}


def verify(provenance_path: Path = PROVENANCE, upstream_root: Path | None = None) -> list[str]:
    """Check all fixture hashes, complete inventory, source mapping and optional bytes."""
    try:
        document = json.loads(provenance_path.read_text(encoding="utf-8"))
        runtime = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"cannot load fixture provenance: {exc}"]
    if not isinstance(document, dict):
        return ["fixture provenance must be an object"]
    if (
        document.get("schema_version") != 1
        or document.get("upstream_revision") != runtime["upstream"]["revision"]
        or document.get("license") != "MIT"
        or not isinstance(document.get("files"), list)
    ):
        return ["fixture provenance schema/revision/license mismatch"]
    errors: list[str] = []
    declared: set[str] = set()

    def check(data: bytes, record: dict, label: str) -> None:
        if record.get("size") != len(data) or record.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"fixture size/SHA-256 mismatch: {label}")
        if upstream_root is not None:
            try:
                original = (upstream_root / record["upstream_source"]).read_bytes()
            except OSError as exc:
                errors.append(f"cannot read upstream fixture {label}: {exc}")
            else:
                if original != data:
                    errors.append(f"upstream fixture bytes differ: {label}")

    for record in document["files"]:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            errors.append("invalid fixture record")
            continue
        relative = record["path"]
        target = (REPOSITORY_ROOT / relative).resolve()
        try:
            local = target.relative_to(FIXTURE_ROOT)
        except ValueError:
            errors.append(f"fixture path outside evidence directory: {relative}")
            continue
        if relative in declared or len(local.parts) != 2 or local.parts[0] not in CATEGORIES or target.suffix != ".bin":
            errors.append(f"invalid or duplicate fixture path: {relative}")
            continue
        declared.add(relative)
        expected_source = f"HarpoS7.Family0.Tests/Blobs/{CATEGORIES[local.parts[0]]}/{local.name}"
        if record.get("upstream_source") != expected_source:
            errors.append(f"fixture source mapping mismatch: {relative}")
            continue
        try:
            data = target.read_bytes()
        except OSError as exc:
            errors.append(f"cannot read fixture {relative}: {exc}")
            continue
        check(data, record, relative)
    actual = {path.relative_to(REPOSITORY_ROOT).as_posix() for path in FIXTURE_ROOT.rglob("*.bin")}
    errors.extend(f"unmanifested known-answer fixture: {path}" for path in sorted(actual - declared))
    errors.extend(f"missing known-answer fixture: {path}" for path in sorted(declared - actual))
    vectors = document.get("transform7_vectors")
    if not isinstance(vectors, list) or len(vectors) != 2:
        return errors + ["exactly two upstream Transform7 vectors are required"]
    names = set()
    for vector in vectors:
        if not isinstance(vector, dict) or vector.get("name") not in {"transform7", "transform7_2"} or vector["name"] in names:
            errors.append("invalid or duplicate Transform7 vector")
            continue
        names.add(vector["name"])
        fields = vector.get("fields")
        if not isinstance(fields, dict) or set(fields) != {"source", "prng1", "prng2", "destination"}:
            errors.append("incomplete Transform7 vector fields")
            continue
        for name, suffix, size in (
            ("source", "src", 40),
            ("prng1", "prng1", 20),
            ("prng2", "prng2", 20),
            ("destination", "dst", 72),
        ):
            record = fields[name]
            if not isinstance(record, dict) or not isinstance(record.get("hex"), str):
                errors.append(f"invalid Transform7 {name} field")
                continue
            expected_source = f"HarpoS7.Family0.Tests/Blobs/Transforms/{vector['name']}-{suffix}.bin"
            if record.get("upstream_source") != expected_source:
                errors.append(f"Transform7 vector source mapping mismatch: {name}")
                continue
            try:
                data = bytes.fromhex(record["hex"])
            except ValueError:
                errors.append(f"invalid Transform7 fixture hex: {name}")
                continue
            if len(data) != size:
                errors.append(f"Transform7 fixture length mismatch: {name}")
            check(data, record, f"{vector['name']}/{name}")
    return errors
