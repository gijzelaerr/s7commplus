#!/usr/bin/env python3
"""Trace possible inputs and assignments for one generated output word.

This is conservative, word-level static data flow, not a proof of bit-level
influence or a cryptographic simplification. Monolith9/10 are traced across
their ordered Part files and shared scratch array.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

_IGNORED_NAMES = {"_U32", "_shr"}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY_ROOT / "old/family0/artifacts.json"


def _reference_sort_key(ref: str) -> tuple[int, int]:
    if ref.startswith("a") and ref[1:].isdigit():
        return (0, int(ref[1:]))
    kind, _, index = ref.partition("[")
    return ({"source": 1, "destination_before": 2, "scratch_initial": 3}[kind], int(index[:-1]))


def format_input_ranges(inputs: list[str]) -> str:
    """Compact consecutive input-word indexes for the human summary."""
    if not inputs:
        return "(constant only)"
    groups: list[str] = []
    kind = ""
    start = end = -1
    for ref in sorted(inputs, key=_reference_sort_key):
        current_kind, _, index_text = ref.partition("[")
        index = int(index_text[:-1])
        if current_kind == kind and index == end + 1:
            end = index
            continue
        if kind:
            groups.append(f"{kind}[{start}]" if start == end else f"{kind}[{start}-{end}]")
        kind, start, end = current_kind, index, index
    groups.append(f"{kind}[{start}]" if start == end else f"{kind}[{start}-{end}]")
    return ", ".join(groups)


@dataclass(frozen=True)
class Assignment:
    id: str
    path: str
    line: int
    end_line: int
    target: str
    parents: tuple[str, ...]


class AssignmentRecord(TypedDict):
    id: str
    path: str
    line: int
    end_line: int
    target: str
    parents: list[str]


class GraphTrace(TypedDict):
    output_word: int
    root: str
    inputs: list[str]
    assignments: list[AssignmentRecord]


class MonolithTrace(GraphTrace):
    monolith: int


class DependencyGraph:
    """Version each assignment while preserving shared array state."""

    def __init__(self) -> None:
        self.assignments: list[Assignment] = []
        self.latest: dict[str, str] = {}

    @staticmethod
    def _indexed_name(node: ast.Subscript) -> str:
        if not isinstance(node.value, ast.Name) or node.value.id not in {"src_dwords", "dst_dwords", "locals_"}:
            raise ValueError(f"unsupported indexed expression at line {node.lineno}")
        if not isinstance(node.slice, ast.Constant) or type(node.slice.value) is not int or node.slice.value < 0:
            raise ValueError(f"dynamic word index at line {node.lineno}")
        return f"{node.value.id}[{node.slice.value}]"

    def _read(self, name: str) -> str:
        if name in self.latest:
            return self.latest[name]
        if name.startswith("src_dwords["):
            return name.replace("src_dwords", "source", 1)
        if name.startswith("dst_dwords["):
            return name.replace("dst_dwords", "destination_before", 1)
        if name.startswith("locals_["):
            return name.replace("locals_", "scratch_initial", 1)
        raise ValueError(f"read of unassigned scalar {name}")

    def _parents(self, expression: ast.expr) -> tuple[str, ...]:
        graph = self

        class Reader(ast.NodeVisitor):
            def __init__(self) -> None:
                self.refs: set[str] = set()

            def visit_Subscript(self, node: ast.Subscript) -> None:
                self.refs.add(graph._read(graph._indexed_name(node)))

            def visit_Name(self, node: ast.Name) -> None:
                if node.id in _IGNORED_NAMES:
                    return
                if node.id.startswith("uVar"):
                    self.refs.add(graph._read(node.id))
                    return
                raise ValueError(f"unsupported name {node.id} at line {node.lineno}")

        reader = Reader()
        reader.visit(expression)
        return tuple(sorted(reader.refs, key=_reference_sort_key))

    def add_execute(self, path: str, source: str) -> None:
        """Analyze one generated ``execute`` in execution order.

        Scalar temporaries are function-local; indexed scratch state survives
        into the next Monolith9/10 Part.
        """
        self.latest = {name: ref for name, ref in self.latest.items() if not name.startswith("uVar")}
        module = ast.parse(source)
        execute = next((item for item in module.body if isinstance(item, ast.FunctionDef) and item.name == "execute"), None)
        if execute is None:
            raise ValueError(f"{path}: no execute function")
        for statement in execute.body:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                continue  # Function docstring.
            if isinstance(statement, ast.Return):
                continue  # This tool traces destination words, not return values.
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                raise ValueError(f"{path}:{statement.lineno}: unsupported statement")
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id in {"src_dwords", "dst_dwords"}:
                if (
                    not isinstance(statement.value, ast.Call)
                    or not isinstance(statement.value.func, ast.Name)
                    or statement.value.func.id != "_to_uints"
                ):
                    raise ValueError(f"{path}:{statement.lineno}: unexpected buffer initialization")
                continue
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "destination":
                if (
                    not isinstance(statement.value, ast.Call)
                    or not isinstance(statement.value.func, ast.Name)
                    or statement.value.func.id != "_from_uints"
                    or len(statement.value.args) != 1
                    or not isinstance(statement.value.args[0], ast.Name)
                    or statement.value.args[0].id != "dst_dwords"
                ):
                    raise ValueError(f"{path}:{statement.lineno}: unexpected destination copy")
                continue  # Final copy from dst_dwords to the byte buffer.
            if isinstance(target, ast.Name) and target.id.startswith("uVar"):
                name = target.id
            elif isinstance(target, ast.Subscript):
                name = self._indexed_name(target)
                if name.startswith("src_dwords["):
                    raise ValueError(f"{path}:{statement.lineno}: source word is written")
            else:
                raise ValueError(f"{path}:{statement.lineno}: unsupported assignment target")
            parents = self._parents(statement.value)  # Read before updating, for self-assignments.
            ref = f"a{len(self.assignments)}"
            self.assignments.append(
                Assignment(ref, path, statement.lineno, statement.end_lineno or statement.lineno, name, parents)
            )
            self.latest[name] = ref

    def trace(self, output_word: int) -> GraphTrace:
        """Return the backward slice for a final destination word."""
        if output_word < 0:
            raise ValueError("output word must be non-negative")
        target = f"dst_dwords[{output_word}]"
        root = self.latest.get(target)
        if root is None:
            raise ValueError(f"no write to {target}")
        by_id = {assignment.id: assignment for assignment in self.assignments}
        visited: set[str] = set()
        leaves: set[str] = set()
        pending = [root]
        while pending:
            ref = pending.pop()
            if not ref.startswith("a"):
                leaves.add(ref)
            elif ref not in visited:
                visited.add(ref)
                pending.extend(by_id[ref].parents)
        return {
            "output_word": output_word,
            "root": root,
            "inputs": sorted(leaves, key=_reference_sort_key),
            "assignments": [
                {
                    "id": item.id,
                    "path": item.path,
                    "line": item.line,
                    "end_line": item.end_line,
                    "target": item.target,
                    "parents": list(item.parents),
                }
                for item in self.assignments
                if item.id in visited
            ],
        }


def trace_monolith(monolith: int, output_word: int, root: Path = REPOSITORY_ROOT, manifest: Path = MANIFEST) -> MonolithTrace:
    """Trace one Monolith, following all Part files for 9 and 10."""
    if monolith not in range(1, 12):
        raise ValueError("monolith must be 1 through 11")
    artifacts = json.loads(manifest.read_text(encoding="utf-8"))["artifacts"]
    generated = {item["path"] for item in artifacts if item["category"] == "generated-source"}
    base = "old/family0/_generated"
    if monolith in (9, 10):
        folder = "nine" if monolith == 9 else "ten"
        paths = [f"{base}/{folder}/part{number}.py" for number in range(1, 12 if monolith == 9 else 4)]
    else:
        paths = [f"{base}/monolith{monolith}.py"]
    graph = DependencyGraph()
    for path in paths:
        if path not in generated:
            raise ValueError(f"generated source missing from manifest: {path}")
        graph.add_execute(path, (root / path).read_text(encoding="utf-8"))
    return {**graph.trace(output_word), "monolith": monolith}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monolith", type=int, choices=range(1, 12))
    parser.add_argument("output_word", type=int, help="zero-based 32-bit destination word")
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable backward slice")
    parser.add_argument("--steps", action="store_true", help="print every contributing assignment")
    args = parser.parse_args(argv)
    try:
        result = trace_monolith(args.monolith, args.output_word)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Monolith{args.monolith} output word {args.output_word}")
        print(f"Possible inputs: {format_input_ranges(result['inputs'])}")
        assignments = result["assignments"]
        print(f"Contributing assignments: {len(assignments)}")
        if args.steps:
            for item in assignments:
                line = item["line"]
                end_line = item["end_line"]
                span = str(line) if line == end_line else f"{line}-{end_line}"
                print(f"{item['id']} {item['path']}:{span} {item['target']} <- {', '.join(item['parents']) or '(constant)'}")
        else:
            counts: dict[str, int] = {}
            for item in assignments:
                path = str(item["path"])
                counts[path] = counts.get(path, 0) + 1
            for path, count in counts.items():
                print(f"  {path}: {count}")
            print("Use --steps for the full line-by-line trace or --json for structured output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
