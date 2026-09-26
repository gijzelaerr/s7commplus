"""Recover every Monolith7 output bit as a shared reduced decision diagram.

Each bit is interpreted symbolically from its versioned backward slice. Only
nodes reachable from that bit survive; source selectors are separated from
the normalized function, allowing equivalent functions to share one diagram.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import TypedDict

from tools.recover_monolith5 import BDD, _literal
from tools.trace_session_auth_bits import trace_output_bits
from tools.trace_session_auth_output import REPOSITORY_ROOT, trace_monolith


class Function(TypedDict):
    inputs: int
    root: int


class Model(TypedDict):
    version: int
    output_words: list[int]
    nodes: list[tuple[int, int, int]]
    functions: list[Function]
    bits: list[tuple[int, list[tuple[int, int]]]]


def recover_model(root: Path = REPOSITORY_ROOT) -> Model:
    """Derive all 1,152 bits without expanding dense Boolean polynomials."""
    functions: list[Function] = []
    function_ids: dict[tuple[int, int], int] = {}
    nodes: list[tuple[int, int, int]] = []
    node_ids: dict[tuple[int, int, int], int] = {}
    bits: list[tuple[int, list[tuple[int, int]]]] = []
    for word in range(36):
        trace = trace_monolith(7, word, root=root)
        paths = {assignment["path"] for assignment in trace["assignments"]}
        if len(paths) != 1 or any(not ref.startswith("source[") for ref in trace["inputs"]):
            raise ValueError("Monolith7 requires single-file, source-only slices")
        module = ast.parse((root / next(iter(paths))).read_text(encoding="utf-8"))
        execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
        wanted = {(assignment["line"], assignment["target"]) for assignment in trace["assignments"]}
        statements: list[tuple[str, ast.expr]] = []
        for statement in execute.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
                name = f"dst_dwords[{_literal(target.slice)}]"
            else:
                continue
            if (statement.lineno, name) in wanted:
                statements.append((name, statement.value))
        candidates = trace_output_bits(7, word, root=root)
        for bit in range(32):
            bdd = BDD(sorted(candidates[bit], key=lambda ref: (ref[1], ref[0])))
            values: dict[str, tuple[int, ...]] = {}
            for name, expression in statements:
                values[name] = bdd.expression(expression, values)
            output = values[f"dst_dwords[{word}]"][bit]
            reachable: set[int] = set()

            def visit(node: int) -> None:
                if node < 2 or node in reachable:
                    return
                reachable.add(node)
                _, low, high = bdd.nodes[node]
                visit(low)
                visit(high)

            visit(output)
            variables = sorted({bdd.nodes[node][0] for node in reachable})
            index = {variable: position for position, variable in enumerate(variables)}
            selectors = [bdd.refs[variable] for variable in variables]
            translated = {0: 0, 1: 1}

            def serialize(node: int) -> int:
                if node not in translated:
                    variable, low, high = bdd.nodes[node]
                    low_id, high_id = serialize(low), serialize(high)
                    key = (index[variable], low_id, high_id)
                    if key not in node_ids:
                        node_ids[key] = len(nodes) + 2
                        nodes.append(key)
                    translated[node] = node_ids[key]
                return translated[node]

            root_id = serialize(output)
            key = (len(selectors), root_id)
            if key not in function_ids:
                function_ids[key] = len(functions)
                functions.append({"inputs": len(selectors), "root": root_id})
            bits.append((function_ids[key], selectors))
    return {"version": 1, "output_words": list(range(36)), "nodes": nodes, "functions": functions, "bits": bits}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--verify", type=Path)
    args = parser.parse_args()
    model = recover_model()
    if args.verify is not None:
        saved = json.loads(args.verify.read_text(encoding="utf-8"))
        if saved != json.loads(json.dumps(model)):
            raise SystemExit("Monolith7 full model differs from generated source")
        print("Monolith7 full model exactly matches the generated source")
    elif args.json:
        print(json.dumps(model, separators=(",", ":")))
    else:
        print(f"Recovered {len(model['functions'])} functions for {len(model['bits'])} output bits")
        print(f"Shared decision nodes: {len(model['nodes'])}")


if __name__ == "__main__":
    main()
