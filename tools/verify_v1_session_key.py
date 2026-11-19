"""Verify the provenance of the SessionKey data taken from HarpoS7.

Checks, offline and without importing the library:

- every public key embedded in ``s7commplus/v1_session_key/keys.py`` against
  ``tests/fixtures/family0/public_keys.json`` (size, SHA-256, upstream file);
- every upstream known-answer fixture in ``tests/fixtures/family0`` against
  ``provenance.json`` (size, SHA-256, upstream file, complete inventory).

``--upstream-root`` also compares those bytes with a HarpoS7 checkout at the
pinned revision. Nothing is downloaded or rewritten, and no PLC is contacted.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests/fixtures/family0"
PROVENANCE = FIXTURE_ROOT / "provenance.json"
PUBLIC_KEYS = FIXTURE_ROOT / "public_keys.json"
KEY_STORE = REPOSITORY_ROOT / "s7commplus/v1_session_key/keys.py"
CATEGORIES = {"transforms": "Transforms"}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _compare_upstream(data: bytes, upstream_root: Path | None, source: str, label: str, errors: list[str]) -> None:
    if upstream_root is None:
        return
    try:
        original = (upstream_root / source).read_bytes()
    except OSError as exc:
        errors.append(f"cannot read upstream file for {label}: {exc}")
        return
    if original != data:
        errors.append(f"upstream bytes differ: {label}")


def embedded_keys(key_store: Path = KEY_STORE) -> dict[str, bytes]:
    """The ``_PUBLIC_KEYS`` literal of the key store, by ``FF:ID`` fingerprint, read without executing it."""
    module = ast.parse(key_store.read_text(encoding="utf-8"))
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


def verify_public_keys(
    manifest_path: Path = PUBLIC_KEYS, upstream_root: Path | None = None, key_store: Path = KEY_STORE
) -> list[str]:
    """Check every embedded public key against the manifest, and the manifest against the key store."""
    try:
        document = _load(manifest_path)
        expected = embedded_keys(key_store)
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        return [f"cannot load the public-key manifest or key store: {exc}"]
    records = document.get("embedded_public_keys") if isinstance(document, dict) else None
    if document.get("schema_version") != 1 or not isinstance(document.get("upstream"), dict) or not isinstance(records, list):
        return ["public-key manifest schema mismatch"]
    errors: list[str] = []
    declared: set[str] = set()
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
            continue
        value = expected[fingerprint]
        if record["size"] != len(value) or record["sha256"] != hashlib.sha256(value).hexdigest():
            errors.append(f"embedded public-key size/SHA-256 mismatch: {fingerprint}")
        _compare_upstream(value, upstream_root, record["upstream_source"], fingerprint, errors)
    errors.extend(f"unmanifested embedded public key: {fingerprint}" for fingerprint in sorted(expected.keys() - declared))
    return errors


def verify_fixtures(
    provenance_path: Path = PROVENANCE, upstream_root: Path | None = None, manifest_path: Path = PUBLIC_KEYS
) -> list[str]:
    """Check all fixture hashes, the complete inventory, the source mapping and, optionally, the upstream bytes."""
    try:
        document = _load(provenance_path)
        upstream = _load(manifest_path)["upstream"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"cannot load fixture provenance: {exc}"]
    if not isinstance(document, dict):
        return ["fixture provenance must be an object"]
    if (
        document.get("schema_version") != 1
        or document.get("upstream_revision") != upstream.get("revision")
        or document.get("license") != "MIT"
        or not isinstance(document.get("files"), list)
    ):
        return ["fixture provenance schema/revision/license mismatch"]
    errors: list[str] = []
    declared: set[str] = set()

    def check(data: bytes, record: dict[str, Any], label: str) -> None:
        if record.get("size") != len(data) or record.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"fixture size/SHA-256 mismatch: {label}")
        _compare_upstream(data, upstream_root, str(record.get("upstream_source")), label, errors)

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
            field = fields[name]
            if not isinstance(field, dict) or not isinstance(field.get("hex"), str):
                errors.append(f"invalid Transform7 {name} field")
                continue
            expected_source = f"HarpoS7.Family0.Tests/Blobs/Transforms/{vector['name']}-{suffix}.bin"
            if field.get("upstream_source") != expected_source:
                errors.append(f"Transform7 vector source mapping mismatch: {name}")
                continue
            try:
                data = bytes.fromhex(field["hex"])
            except ValueError:
                errors.append(f"invalid Transform7 fixture hex: {name}")
                continue
            if len(data) != size:
                errors.append(f"Transform7 fixture length mismatch: {name}")
            check(data, field, f"{vector['name']}/{name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--upstream-root", type=Path, help="a HarpoS7 checkout at the pinned revision")
    args = parser.parse_args(argv)
    errors = verify_public_keys(upstream_root=args.upstream_root) + verify_fixtures(upstream_root=args.upstream_root)
    if errors:
        print("SessionKey provenance verification failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Verified the embedded HarpoS7 public keys and the upstream known-answer fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
