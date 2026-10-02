#!/usr/bin/env python3
"""Verify the generated monolith code against a pinned HarpoS7 checkout.

The transpiler emits unformatted Python and embeds the source file's local
path in its docstring. AST comparison verifies the generated program while
ignoring only formatting and that path; artifacts.json checks exact file bytes.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

from transpile_harpo_monolith import emit_python, transpile_monolith

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY_ROOT / "old/family0/artifacts.json"


def _normalized_ast(source: str) -> str:
    # The generated file starts with a module docstring, including opening quotes.
    normalized = re.sub(r'\A"""Auto-generated from [^\n]+', '"""Auto-generated from SOURCE.', source)
    return ast.dump(ast.parse(normalized), include_attributes=False)


def verify(upstream_root: Path) -> list[str]:
    """Return mismatches between source-derived and checked-in monolith code."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected_revision = manifest["upstream"]["revision"]
    try:
        actual_revision = subprocess.check_output(
            ["git", "-C", str(upstream_root), "rev-parse", "HEAD"], text=True, stderr=subprocess.PIPE
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"cannot identify HarpoS7 checkout revision: {exc}"]
    if actual_revision != expected_revision:
        return [f"HarpoS7 revision mismatch: expected {expected_revision}, found {actual_revision}"]

    errors = []
    for artifact in manifest["artifacts"]:
        if artifact["category"] != "generated-source":
            continue
        source_path = upstream_root / artifact["upstream_source"]
        output_path = REPOSITORY_ROOT / artifact["path"]
        try:
            source = source_path.read_text(encoding="utf-8")
            checked_in = output_path.read_text(encoding="utf-8")
            generated = emit_python(transpile_monolith(source, source_path.stem), str(source_path))
            if _normalized_ast(generated) != _normalized_ast(checked_in):
                errors.append(f"transpiled program mismatch: {artifact['path']}")
        except (OSError, ValueError, SyntaxError) as exc:
            errors.append(f"cannot verify {artifact['path']}: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", required=True, type=Path)
    args = parser.parse_args(argv)
    errors = verify(args.upstream_root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("Verified all transpiled monolith programs against pinned HarpoS7 source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
