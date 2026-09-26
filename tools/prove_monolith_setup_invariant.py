"""Prove the hidden upper encoding invariant needed by Transform7 setup.

Checkout-only source proof, not a runtime replacement. The 23 truth tables
continue the decoder above its 168-bit payload; membership denotes encoded
zero. Their discovery is not evidence: every preservation query must be UNSAT.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from tools.prove_monolith4_span_identity import boolean_backend, symbolic_source
from tools.recover_monolith4_span_identity import input_gate_diagram, normalized_terms, output_bit_diagram, output_gate_diagram

UPPER_ZERO_TRIPLES = (
    (3, 4, 6, 7),
    (0, 2, 4, 5),
    (0, 4, 5, 6),
    (0, 2, 3, 7),
    (2, 3, 4, 6),
    (0, 2, 4, 5),
    (0, 2, 6, 7),
    (0, 2, 4, 5),
    (1, 3, 4, 5),
    (1, 3, 6, 7),
    (0, 4, 5, 7),
    (1, 2, 3, 6),
    (0, 2, 4, 5),
    (0, 2, 6, 7),
    (0, 2, 4, 5),
    (1, 2, 3, 6),
    (0, 1, 4, 6),
    (1, 3, 4, 5),
    (0, 4, 5, 6),
    (0, 1, 2, 5),
    (0, 1, 2, 4),
    (0, 1, 5, 7),
    (3, 4, 5, 7),
)


def allowed_triple(z3: Any, bits: list[Any], allowed: tuple[int, ...]) -> Any:
    if len(bits) != 3 or not allowed or any(type(k) is not int or not 0 <= k < 8 for k in allowed):
        raise ValueError("expected three bits and valid triple codes")
    return z3.Or(*[z3.And(*[bit if code >> i & 1 else z3.Not(bit) for i, bit in enumerate(bits)]) for code in allowed])


def local_queries(number: int) -> tuple[Any, list[Any], list[tuple[str, Any]]]:
    if number not in (3, 4, 5, 6):
        raise ValueError("unsupported setup kernel")
    z3, source, _ = symbolic_source(number)
    backend = boolean_backend(z3, len(source))
    assumptions = []
    for span in range(2 if number in (3, 4) else 3):
        for term in normalized_terms()[1][-2:]:
            gate = input_gate_diagram(term, span, backend)
            assumptions.append(gate if term.weight < 0 else z3.Not(gate))
        for bit, allowed in enumerate(UPPER_ZERO_TRIPLES, 9):
            values = [backend.variables[backend.ref_index[span * 18 + 15 + member, bit]] for member in range(3)]
            assumptions.append(allowed_triple(z3, values, allowed))
    if number == 3:
        assumptions.extend(z3.Not(backend.variables[backend.ref_index[36 + k // 32, k % 32]]) for k in range(162, 192))
    if number == 5:
        return (
            z3,
            assumptions,
            [("packed_streams_below_2_167", z3.Or(*[output_bit_diagram(6 * span + 5, 29, backend, 5) for span in range(2)]))],
        )
    spans = range(1 if number == 4 else 2)
    top = normalized_terms()[1][-1]
    queries = [("payload_bit_167_zero", z3.Or(*[output_gate_diagram(top, backend, number, span) for span in spans]))]
    for bit, allowed in enumerate(UPPER_ZERO_TRIPLES, 9):
        mismatch = []
        for span in spans:
            values = [output_bit_diagram(span * 18 + 15 + member, bit, backend, number) for member in range(3)]
            mismatch.append(z3.Not(allowed_triple(z3, values, allowed)))
        queries.append((f"upper_bit_{bit + 159}_zero", z3.Or(*mismatch)))
    return z3, assumptions, queries


def prove(timeout_ms: int = 10000, progress: bool = False) -> dict[str, Any]:
    if timeout_ms <= 0:
        raise ValueError("expected positive solver timeout")
    rows = []
    for number in (3, 4, 5, 6):
        z3, assumptions, queries = local_queries(number)
        for name, mismatch in queries:
            solver = z3.Tactic("sat").solver()
            solver.set(timeout=timeout_ms)
            solver.add(*assumptions, mismatch)
            start = time.monotonic()
            result = solver.check()
            row = {
                "monolith": number,
                "stage": name,
                "result": str(result),
                "proved": result == z3.unsat,
                "elapsed_seconds": round(time.monotonic() - start, 6),
            }
            if result == z3.unknown:
                row["reason"] = solver.reason_unknown()
            rows.append(row)
            if progress:
                print(json.dumps(row), file=sys.stderr, flush=True)
    folder = Path(__file__).resolve().parents[1] / "s7commplus/session_auth/family0/_generated"
    return {
        "scope": "local upper-zero encoding preservation under input B<2^166; Monolith3 additionally N<2^162",
        "source_sha256": {
            f"monolith{number}.py": hashlib.sha256((folder / f"monolith{number}.py").read_bytes()).hexdigest()
            for number in (3, 4, 5, 6)
        },
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "upper_zero_triples": UPPER_ZERO_TRIPLES,
        "z3_version": z3.get_version_string(),
        "solver_budget_per_stage_ms": timeout_ms,
        "expected_stages": 73,
        "full_proof": len(rows) == 73 and all(row["proved"] for row in rows),
        "stages": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args()
    report = prove(args.timeout_ms, args.progress)
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
