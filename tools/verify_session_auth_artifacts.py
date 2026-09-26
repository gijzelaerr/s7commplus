#!/usr/bin/env python3
"""Verify the SessionKey generated-artifact inventory, sizes, and SHA-256 hashes."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPOSITORY_ROOT / "s7commplus/session_auth/artifacts.json"
GENERATED_ROOT = REPOSITORY_ROOT / "s7commplus/session_auth/family0/_generated"


def _is_artifact(path: Path) -> bool:
    # Include handwritten package glue: data/__init__.py embeds SHARED_DATA.
    return path.suffix in {".bin", ".py"}


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(document.get("artifacts"), list):
        raise ValueError("manifest must use schema_version 1 and contain an artifacts list")
    return document


def verify(manifest_path: Path = DEFAULT_MANIFEST) -> list[str]:
    """Return actionable validation errors; an empty list means success."""
    try:
        document = _load_manifest(manifest_path)
    except ValueError as exc:
        return [str(exc)]

    errors: list[str] = []
    declared: set[str] = set()
    required = {"path", "category", "upstream_source", "generation", "size", "sha256"}
    for index, artifact in enumerate(document["artifacts"]):
        if not isinstance(artifact, dict) or not required.issubset(artifact):
            errors.append(f"artifact entry {index} is missing required fields: {sorted(required)}")
            continue
        relative = artifact["path"]
        if not isinstance(relative, str) or relative in declared:
            errors.append(f"artifact entry {index} has an invalid or duplicate path: {relative!r}")
            continue
        declared.add(relative)
        target = (REPOSITORY_ROOT / relative).resolve()
        try:
            target.relative_to(GENERATED_ROOT.resolve())
        except ValueError:
            errors.append(f"manifest path is outside the generated artifact directory: {relative}")
            continue
        if not target.is_file():
            errors.append(f"missing generated artifact: {relative}")
            continue
        data = target.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        if artifact["size"] != len(data):
            errors.append(f"size mismatch for {relative}: manifest={artifact['size']}, actual={len(data)}")
        if artifact["sha256"] != actual_hash:
            errors.append(f"SHA-256 mismatch for {relative}: manifest={artifact['sha256']}, actual={actual_hash}")

    actual = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in GENERATED_ROOT.rglob("*")
        if path.is_file() and _is_artifact(path)
    }
    for relative in sorted(actual - declared):
        errors.append(f"unmanifested generated artifact: {relative}")
    for relative in sorted(declared - actual):
        errors.append(f"manifest entry is not a generated runtime artifact: {relative}")
    errors.extend(_verify_embedded_keys(document))
    return errors


def _verify_embedded_keys(document: dict[str, Any]) -> list[str]:
    """Inventory the vendored data within the human-maintained key store."""
    # Keep the default verifier/pre-commit hook standard-library-only. Do not
    # import the library or execute handwritten source while auditing data.
    try:
        expected = embedded_keys()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"cannot decode embedded public-key store: {exc}"]
    records = document.get("embedded_public_keys")
    if not isinstance(records, list):
        return ["manifest is missing embedded_public_keys inventory"]
    errors, declared = [], set()
    for record in records:
        if not isinstance(record, dict) or not {"fingerprint", "size", "sha256", "upstream_source"}.issubset(record):
            errors.append("invalid embedded public-key record")
            continue
        fingerprint = record["fingerprint"]
        if not isinstance(fingerprint, str) or fingerprint in declared or fingerprint not in expected:
            errors.append(f"invalid or duplicate embedded public key: {fingerprint!r}")
            continue
        declared.add(fingerprint)
        family, key_id = fingerprint.split(":")
        if record["upstream_source"] != f"HarpoS7.PublicKeys/Keys/{family}/{key_id}.bin":
            errors.append(f"embedded public-key source mismatch: {fingerprint}")
        value = expected[fingerprint]
        if record["size"] != len(value) or record["sha256"] != hashlib.sha256(value).hexdigest():
            errors.append(f"embedded public-key size/SHA-256 mismatch: {fingerprint}")
    errors.extend(f"unmanifested embedded public key: {fingerprint}" for fingerprint in sorted(expected.keys() - declared))
    formats = document.get("binary_formats")
    binary_names = {path.name for path in GENERATED_ROOT.rglob("*.bin")}
    if (
        not isinstance(formats, dict)
        or set(formats) != binary_names
        or not all(isinstance(value, str) and value for value in formats.values())
    ):
        errors.append("binary format inventory differs from runtime tables")
    return errors


def embedded_keys() -> dict[str, bytes]:
    module = ast.parse((REPOSITORY_ROOT / "s7commplus/session_auth/keys.py").read_text(encoding="utf-8"))
    family_class = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "KeyFamily")
    families = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in family_class.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
    }
    table = next(
        node.value
        for node in module.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "_PUBLIC_KEYS"
    )
    if not isinstance(table, ast.Dict):
        raise ValueError("expected a literal public-key dictionary")
    result = {}
    for key, value in zip(table.keys, table.values):
        if not (
            isinstance(key, ast.Tuple)
            and len(key.elts) == 2
            and isinstance(key.elts[0], ast.Attribute)
            and isinstance(key.elts[0].value, ast.Name)
            and key.elts[0].value.id == "KeyFamily"
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == "bytes"
            and value.func.attr == "fromhex"
            and len(value.args) == 1
            and not value.keywords
        ):
            raise ValueError("unsupported public-key entry")
        family, identifier = families[key.elts[0].attr], ast.literal_eval(key.elts[1])
        fingerprint = f"{family:02X}:{identifier}"
        if fingerprint in result:
            raise ValueError("duplicate public-key entry")
        result[fingerprint] = bytes.fromhex(ast.literal_eval(value.args[0]))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    errors = verify(args.manifest)
    if errors:
        print("SessionKey artifact verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print(
            "Regenerate the affected output from the pinned HarpoS7 revision or update artifacts.json with reviewed provenance.",
            file=sys.stderr,
        )
        return 1
    print("Verified all SessionKey generated artifacts against artifacts.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
