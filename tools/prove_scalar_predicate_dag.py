"""Prove typed shared predicate equations against the actual helper ASTs.

Optional development-only Z3. Nine primitive frontend obligations on canonical
residues and arbitrary Boolean lifts. No curve relation, first-defect catalogue
or whole-stage equivalence claim. Integer operations here fit signed322 bits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import operator
from pathlib import Path
from typing import Any

from tools import scalar_representative_rules as rules
from tools import scalar_lift_categories as categories
from tools.prove_scalar_predicate_guards import compile_guard
from tools.scalar_predicate_dag import Backend, P

WIDTH = 322


def prove(timeout_ms: int = 10000) -> dict[str, object]:
    import z3

    if timeout_ms <= 0:
        raise ValueError("positive solver timeout required")
    context = z3.Context()
    a, b = [z3.BitVec(name, WIDTH, ctx=context) for name in ("a", "b")]
    ta, tb, defective = [z3.Bool(name, ctx=context) for name in ("ta", "tb", "defective")]
    rows = []
    names = (
        "lazy_addition_defect",
        "lazy_subtraction_defect",
        "nonzero_product_lift",
        "subtraction_lift",
        "addition_lift",
        "square_lift",
        "small_nonzero_product_lift",
    )
    helpers = tuple((rules, name) for name in names) + (
        (categories, "small_addition_lift"),
        (categories, "small_subtraction_lift"),
    )
    for module, name in helpers:
        backend = Backend()
        symbols = {"a": backend.field(0), "b": backend.field(1), "lift_a": backend.lift(0), "lift_b": backend.lift(1)}
        source_inputs = {"a": a, "b": b, "lift_a": ta, "lift_b": tb}
        if name == "addition_lift":
            symbols["s"], source_inputs["s"] = symbols["a"] + symbols["b"], a + b
        if name in ("subtraction_lift", "small_addition_lift", "small_subtraction_lift"):
            symbols["defective"], source_inputs["defective"] = backend.lift(2), defective
        root = compile_guard(backend, name, symbols, module=module)
        source = compile_guard(z3, name, source_inputs, module=module)
        expressions: list[Any] = []
        functions = {
            "add": operator.add,
            "subtract": operator.sub,
            "multiply": operator.mul,
            "mask": operator.and_,
            "lt": operator.lt,
            "le": operator.le,
            "ge": operator.ge,
            "eq": operator.eq,
        }
        for index, node in enumerate(backend.nodes):
            op, args = node.operation, node.arguments
            if op in ("integer", "boolean", "field", "lift"):
                if op == "integer":
                    value = z3.BitVecVal(args[0], WIDTH, ctx=context)
                elif op == "boolean":
                    value = z3.BoolVal(bool(args[0]), ctx=context)
                elif op == "field":
                    value = (a, b)[args[0]]
                else:
                    value = (ta, tb, defective)[args[0]]
            else:
                if any(not 0 <= child < index for child in args):
                    raise ValueError("forward predicate equation")
                if op in ("and", "or"):
                    value = (z3.And if op == "and" else z3.Or)(*[expressions[i] for i in args])
                elif op == "not":
                    value = z3.Not(expressions[args[0]])
                elif op in functions:
                    value = functions[op](expressions[args[0]], expressions[args[1]])
                else:
                    raise ValueError("unsupported predicate equation")
            expressions.append(value)
        solver = z3.Solver(ctx=context)
        solver.set(timeout=timeout_ms)
        solver.add(0 <= a, a < P, 0 <= b, b < P, z3.Xor(source, expressions[root.index]))
        result = solver.check()
        row = {"name": name, "result": str(result), "proved": result == z3.unsat}
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        rows.append(row)
    return {
        "scope": "nine actual primitive predicate ASTs vs typed equation DAG; canonical residues; arbitrary Boolean lifts; NOT catalogue/whole-stage proof",
        "full_proof": all(row["proved"] for row in rows),
        "z3_version": z3.get_version_string(),
        "obligations": rows,
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "scalar_predicate_dag.py",
                "prove_scalar_predicate_dag.py",
                "prove_scalar_predicate_guards.py",
                "scalar_representative_rules.py",
                "scalar_lift_categories.py",
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    report = prove(parser.parse_args().timeout_ms)
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
