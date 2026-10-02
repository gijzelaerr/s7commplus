#!/usr/bin/env python3
"""Map indexed inputs and outputs of the generated Family-0 transforms.

This is a *syntactic* map, not a claim that an output depends on every listed
input. It leaves the byte-verified generated code untouched and gives a small
starting point for targeted data-flow analysis.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY_ROOT / "old/family0/artifacts.json"
_BUFFERS = ("src_dwords", "dst_dwords", "locals_")


def map_execute(source: str) -> dict[str, dict[str, list[int]]]:
    """Return constant-index reads and writes inside ``execute``.

    Reject dynamic indexes rather than silently omitting part of a transform.
    Indices are 32-bit words, not byte offsets.
    """
    module = ast.parse(source)
    execute = next((node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute"), None)
    if execute is None:
        raise ValueError("no execute function")

    accesses: dict[str, dict[str, set[int]]] = {name: {"read": set(), "write": set()} for name in _BUFFERS}
    for node in ast.walk(execute):
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name):
            continue
        name = node.value.id
        if name not in accesses:
            continue
        if not isinstance(node.slice, ast.Constant) or not isinstance(node.slice.value, int) or node.slice.value < 0:
            raise ValueError(f"dynamic {name} index at line {node.lineno}")
        access = "write" if isinstance(node.ctx, ast.Store) else "read"
        accesses[name][access].add(node.slice.value)
    return {name: {access: sorted(indexes) for access, indexes in directions.items()} for name, directions in accesses.items()}


def map_artifacts(manifest: Path = MANIFEST, root: Path = REPOSITORY_ROOT) -> list[dict[str, object]]:
    """Map every source artifact listed in the provenance manifest."""
    inventory = json.loads(manifest.read_text(encoding="utf-8"))
    result: list[dict[str, object]] = []
    for artifact in inventory["artifacts"]:
        if artifact["category"] != "generated-source":
            continue
        path = root / artifact["path"]
        result.append(
            {
                "path": artifact["path"],
                "upstream_source": artifact["upstream_source"],
                "word_accesses": map_execute(path.read_text(encoding="utf-8")),
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", help="show only this manifest-relative generated source path")
    args = parser.parse_args(argv)
    records = map_artifacts()
    if args.path:
        records = [record for record in records if record["path"] == args.path]
        if not records:
            parser.error(f"no generated source matches {args.path!r}")
    print(json.dumps(records, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
