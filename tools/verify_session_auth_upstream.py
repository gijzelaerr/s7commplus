#!/usr/bin/env python3
"""Derive Family-0 data from a pinned HarpoS7 checkout and compare it.

This command does not download source or alter runtime files. Pass a checkout
of the revision pinned by artifacts.json with ``--upstream-root``. Use
``--output-dir`` to write the four generated binaries into a new directory.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUTH_ROOT = REPOSITORY_ROOT / "s7commplus/session_auth"
DATA_ROOT = AUTH_ROOT / "family0/_generated/data"
HEX_NUMBER = re.compile(r"0[xX][0-9A-Fa-f]+")


def _braced(source: str, opening: int) -> str:
    """Return the text within the balanced brace at *opening*."""
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise ValueError("unterminated C# array initializer")


def _array(source: str, declaration: str) -> list[int]:
    match = re.search(r"\b" + re.escape(declaration) + r"\b[\s\S]*?=\s*new\s+\w+\[[^]]*\]\s*\{", source)
    if match is None:
        raise ValueError(f"missing C# array initializer: {declaration}")
    return [int(value, 16) for value in HEX_NUMBER.findall(_braced(source, match.end() - 1))]


def _collection(source: str, name: str) -> bytes:
    match = re.search(r"\b" + re.escape(name) + r"\b[\s\S]*?=\s*new\s+ushort\[[^]]*\]\[\]\s*\{", source)
    if match is None:
        raise ValueError(f"missing fingerprint collection: {name}")
    body = _braced(source, match.end() - 1)
    arrays = [
        [int(value, 16) for value in HEX_NUMBER.findall(_braced(body, item.end() - 1))]
        for item in re.finditer(r"new\s+ushort\[\]\s*\{", body)
    ]
    if len(arrays) != 20:
        raise ValueError(f"{name} has {len(arrays)} arrays, expected 20")
    if any(value > 0xFFFF for values in arrays for value in values):
        raise ValueError(f"{name} contains a value outside ushort range")
    return struct.pack("<20I", *(len(values) for values in arrays)) + b"".join(
        struct.pack(f"<{len(values)}H", *values) for values in arrays
    )


def _constants() -> dict[str, Any]:
    source = ast.parse((DATA_ROOT / "_constants.py").read_text(encoding="utf-8"))
    return {
        node.target.id: ast.literal_eval(node.value)
        for node in source.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None
    }


def _shared_data() -> bytes:
    source = ast.parse((DATA_ROOT / "__init__.py").read_text(encoding="utf-8"))
    for node in source.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "SHARED_DATA":
            if isinstance(node.value, ast.Call) and len(node.value.args) == 1:
                return bytes.fromhex(ast.literal_eval(node.value.args[0]))
    raise ValueError("cannot locate SHARED_DATA literal")


def _mutations(source: str) -> tuple[tuple[tuple[int, str, int], ...], ...]:
    result = []
    for number in range(1, 21):
        match = re.search(r"private\s+static\s+void\s+Mutate" + str(number) + r"\s*\([^)]*\)\s*\{", source)
        if match is None:
            raise ValueError(f"missing upstream Mutate{number}")
        body = _braced(source, match.end() - 1)
        operations = re.findall(r"dataArray\[(\d+)\]\s*([*+^])=\s*(0[xX][0-9A-Fa-f]+)\s*;", body)
        if len(operations) != body.count("dataArray["):
            raise ValueError(f"unsupported statement in upstream Mutate{number}")
        result.append(tuple((int(index), operator, int(value, 16)) for index, operator, value in operations))
    return tuple(result)


def verify(upstream_root: Path, output_dir: Path | None = None) -> list[str]:
    """Compare pinned upstream inputs with every extracted Family-0 data table."""
    manifest = json.loads((AUTH_ROOT / "artifacts.json").read_text(encoding="utf-8"))
    revision = manifest["upstream"]["revision"]
    try:
        actual_revision = subprocess.check_output(
            ["git", "-C", str(upstream_root), "rev-parse", "HEAD"], text=True, stderr=subprocess.PIPE
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"cannot identify HarpoS7 checkout revision: {exc}"]
    if actual_revision != revision:
        return [f"HarpoS7 revision mismatch: expected {revision}, found {actual_revision}"]

    try:
        data_root = upstream_root / "HarpoS7.Family0/Data"
        fingerprint_root = upstream_root / "HarpoS7/Fingerprint"
        transform12 = (data_root / "Transform12Data.cs").read_text(encoding="utf-8")
        fingerprint = (fingerprint_root / "FingerprintConsts.cs").read_text(encoding="utf-8")
        patch_revision = next(
            patch["revision"]
            for patch in manifest["upstream_patches"]
            if patch["artifact"] == "s7commplus/session_auth/family0/_generated/data/fp_data2.bin"
        )
        patched_fingerprint = subprocess.check_output(
            ["git", "-C", str(upstream_root), "show", f"{patch_revision}:HarpoS7/Fingerprint/FingerprintConsts.cs"],
            text=True,
            stderr=subprocess.PIPE,
        )
        binaries = {
            "transform12_metadata.bin": (data_root / "Blobs/Transform12Metadata.bin").read_bytes(),
            "transform12_big_int_data.bin": bytes(_array(transform12, "BigIntData")),
            "fp_data1.bin": _collection(fingerprint, "Data1Collection"),
            "fp_data2.bin": _collection(patched_fingerprint, "Data2Collection"),
        }
        constants = _constants()
        upstream_constants: dict[str, Any] = {
            "TRANSFORM1_DATA_INTS": tuple(_array((data_root / "Transform1Data.cs").read_text(), "Data")),
            "TRANSFORM7_INDEXES_INTS": tuple(_array((data_root / "Transform7Data.cs").read_text(), "Indexes")),
            "TRANSFORM7_COUNTS_INTS": tuple(_array((data_root / "Transform7Data.cs").read_text(), "Counts")),
            "FP_BIG_CONTEXT_INIT_INTS": tuple(_array(fingerprint, "BigContextInitialValue")),
            "FP_XOR_MAGIC_INTS": tuple(_array(fingerprint, "XorMagic")),
            "FP_MUTATIONS": _mutations((fingerprint_root / "ContextMutator.cs").read_text()),
        }
        transform7_data = bytes(_array((data_root / "Transform7Data.cs").read_text(), "Data"))
        shared_data = _array((data_root / "SharedData.cs").read_text(), "Data")
    except (OSError, ValueError, StopIteration, subprocess.CalledProcessError) as exc:
        return [f"cannot parse pinned HarpoS7 source: {exc}"]

    if output_dir is not None:
        try:
            output_dir.mkdir(parents=True, exist_ok=False)
            for name, data in binaries.items():
                (output_dir / name).write_bytes(data)
        except OSError as exc:
            return [f"cannot write generated binaries to new directory {output_dir}: {exc}"]

    errors = []
    for name, expected in binaries.items():
        if (DATA_ROOT / name).read_bytes() != expected:
            errors.append(f"upstream data mismatch: {name}")
    for name, expected in upstream_constants.items():
        if constants.get(name) != expected:
            errors.append(f"upstream data mismatch: _constants.py:{name}")
    if bytes.fromhex(constants["TRANSFORM7_DATA_HEX"]) != transform7_data:
        errors.append("upstream data mismatch: _constants.py:TRANSFORM7_DATA_HEX")
    if _shared_data() != struct.pack(f"<{len(shared_data)}I", *shared_data):
        errors.append("upstream data mismatch: SHARED_DATA")
    from s7commplus.session_auth.keys import _PUBLIC_KEYS

    for (family, key_id), value in _PUBLIC_KEYS.items():
        relative = f"HarpoS7.PublicKeys/Keys/{int(family):02X}/{key_id}.bin"
        try:
            original = (upstream_root / relative).read_bytes()
        except OSError as exc:
            errors.append(f"cannot read upstream public key {relative}: {exc}")
        else:
            if original != value:
                errors.append(f"upstream public-key mismatch: {relative}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path, help="write the four generated binaries into a new directory")
    args = parser.parse_args(argv)
    errors = verify(args.upstream_root, args.output_dir)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("Verified Family-0 binary tables and constants against pinned HarpoS7 source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
