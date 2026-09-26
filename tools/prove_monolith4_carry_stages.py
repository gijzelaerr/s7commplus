"""Prove decoded Monolith4 carry transitions, with sound cone abstraction.

Cut signals are independent Boolean variables. UNSAT of a generalized cone
proves the original equation; SAT is only an abstraction failure, not a source
counterexample. Install the optional development-only analysis extra.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections.abc import Callable
from functools import lru_cache
from typing import Any
from pathlib import Path

from s7commplus.session_auth.family0._generated import monolith4
from tools.prove_monolith4_span_identity import boolean_backend, symbolic_source, verify_translation
from tools.recover_monolith4_span_identity import input_gate_diagram, normalized_terms, output_gate_diagram


def equations() -> tuple[Any, Any, list[tuple[str, Any, frozenset[int]]]]:
    z3, source, output = symbolic_source()
    backend = boolean_backend(z3)
    boundary, terms = normalized_terms()
    left, right, sums = [], [], []
    for term in terms:
        a = input_gate_diagram(term, 0, backend)
        b = input_gate_diagram(term, 1, backend)
        s = output_gate_diagram(term, backend)
        if term.weight < 0:
            a, b, s = z3.Not(a), z3.Not(b), z3.Not(s)
        left.append(a)
        right.append(b)
        sums.append(s)
    lb = input_gate_diagram(boundary, 0, backend)
    rb = input_gate_diagram(boundary, 1, backend)
    hb = output_gate_diagram(boundary, backend)
    verify_translation(z3, source, output, backend, hb, sums)
    carries = [z3.Xor(z3.Xor(s, a), b) for a, b, s in zip(left, right, sums)]

    def local_refs(selected: tuple[Any, ...]) -> frozenset[int]:
        return frozenset(
            backend.variables[backend.ref_index[(span * 18 + term.chunk * 3 + member, term.bit)]].get_id()
            for term in selected
            for span in range(2)
            for member in range(3)
        )

    stages = [
        ("boundary", z3.Xor(hb, z3.Xor(lb, rb)), local_refs((boundary,))),
        ("initial_carry", z3.Xor(carries[0], z3.And(lb, rb)), local_refs((boundary, terms[0]))),
    ]
    for bit in range(167):
        expected = z3.Or(z3.And(left[bit], right[bit]), z3.And(left[bit], carries[bit]), z3.And(right[bit], carries[bit]))
        stages.append((f"carry_{bit}_to_{bit + 1}", z3.Xor(carries[bit + 1], expected), local_refs((terms[bit], terms[bit + 1]))))
    return z3, backend, stages


def abstract_cone(
    z3: Any, root: Any, local: frozenset[int], expanded: frozenset[int] = frozenset()
) -> tuple[Any, dict[int, Any]]:
    """Generalize nonlocal sub-DAGs consistently; keep constants unchanged."""
    cuts: dict[int, Any] = {}
    originals: dict[int, Any] = {}

    @lru_cache(maxsize=None)
    def has_local(node: Any) -> bool:
        return node.get_id() in local or any(has_local(child) for child in node.children())

    @lru_cache(maxsize=None)
    def visit(node: Any) -> Any:
        if z3.is_true(node) or z3.is_false(node):
            return node
        if not has_local(node) and node.get_id() not in expanded:
            identifier = node.get_id()
            if identifier not in cuts:
                cuts[identifier] = z3.Bool(f"cut_{identifier}")
                originals[identifier] = node
            return cuts[identifier]
        children = node.children()
        return node.decl()(*(visit(child) for child in children)) if children else node

    return visit(root), originals


def proof_progress(results: list[dict[str, Any]], start: int, stop: int) -> tuple[int, bool]:
    """Count only an uninterrupted induction chain, never completing partial runs."""
    prefix = 0
    if start == 0 and len(results) >= 2 and results[0]["proved"] and results[1]["proved"]:
        prefix = 1
        for row in results[2:]:
            if not row["proved"]:
                break
            prefix += 1
    complete = start == 0 and stop == 169 and len(results) == 169 and all(row["proved"] for row in results)
    return prefix, complete


def prove(
    timeout_ms: int = 1000,
    start: int = 0,
    stop: int = 169,
    refinements: int = 12,
    abstraction: bool = False,
    continue_after_failure: bool = False,
    retain_lemmas: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if timeout_ms <= 0 or refinements < 0 or not 0 <= start < stop <= 169:
        raise ValueError("expected positive timeout and a range inside 0..169")
    z3, backend, stages = equations()
    results = []
    shared_solver = z3.Tactic("sat").solver()
    for name, mismatch, local in stages[start:stop]:
        expanded: frozenset[int] = frozenset()
        # Keep the shared source DAG intact. Pre-simplification changes the
        # SAT encoding and can make otherwise tractable carry queries stall.
        root = mismatch
        began = time.monotonic()
        deadline = began + timeout_ms / 1000
        for depth in range(refinements + 1):
            if abstraction:
                abstracted, cuts = abstract_cone(z3, root, local, expanded)
            else:
                abstracted, cuts = root, {}
            solver = shared_solver if retain_lemmas and not abstraction else z3.Tactic("sat").solver()
            solver.set(timeout=max(1, int((deadline - time.monotonic()) * 1000)))
            if abstraction or not retain_lemmas:
                solver.add(abstracted)
                result = solver.check()
            else:
                query = z3.Bool(f"stage_query_{len(results)}")
                solver.add(query == abstracted)
                result = solver.check(query)
                if result == z3.unsat:
                    # This equality is now a proved theorem, not an assumed
                    # constraint on reachable input values or encoded state.
                    solver.add(z3.Not(query))
            if result != z3.sat or not cuts or time.monotonic() >= deadline:
                break
            expanded |= cuts.keys()
        row = {
            "stage": name,
            "result": str(result),
            "independent_cut_signals": len(cuts),
            "refinements": depth,
            "proved": result == z3.unsat,
            "elapsed_seconds": round(time.monotonic() - began, 6),
        }
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        results.append(row)
        if progress is not None:
            progress(row.copy())
        if result != z3.unsat and not continue_after_failure:
            break
    prefix, complete = proof_progress(results, start, stop)
    return {
        "scope": "source carry induction; generalized-cone SAT is not a source counterexample",
        "abstraction": abstraction,
        "backend": "Z3 SAT tactic over the unsimplified demanded-bit source DAG",
        "stage_range": [start, stop],
        "solver_budget_per_stage_ms": timeout_ms,
        "retain_lemmas": retain_lemmas and not abstraction,
        "source_sha256": hashlib.sha256(Path(monolith4.__file__).read_bytes()).hexdigest(),
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "z3_version": z3.get_version_string(),
        "translation_controls": 8,
        "proved_payload_prefix_bits": prefix,
        "full_proof": complete,
        "stages": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int, default=169)
    parser.add_argument("--refinements", type=int, default=12)
    parser.add_argument("--abstract", action="store_true")
    parser.add_argument("--continue-after-failure", action="store_true")
    parser.add_argument("--retain-lemmas", action="store_true")
    parser.add_argument("--progress", action="store_true", help="write stage results to stderr; stdout stays JSON")
    args = parser.parse_args()
    report = prove(
        args.timeout_ms,
        args.start,
        args.stop,
        args.refinements,
        args.abstract,
        args.continue_after_failure,
        args.retain_lemmas,
        (lambda row: print(json.dumps(row), file=sys.stderr, flush=True)) if args.progress else None,
    )
    print(json.dumps(report, indent=2))
    if not all(row["proved"] for row in report["stages"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
