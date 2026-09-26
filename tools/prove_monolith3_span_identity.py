"""Prove Monolith3's decoded pair identity with a virtual plain-input span.

Local integer carry proofs cover all uint32 inputs; plain bits 170..191 cancel
from the decoded pair sum, not necessarily the individual encoded outputs.
Optional development-only Z3 dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from s7commplus.session_auth.family0._generated import monolith3
from tools.prove_monolith6_span_identity import local_equations


def prove(timeout_ms: int = 10000, bits: int = 168, progress: bool = False) -> dict[str, Any]:
    if timeout_ms <= 0 or not 1 <= bits <= 168:
        raise ValueError("expected positive timeout and 1..168 bits")
    z3, stages = local_equations(3)
    results = []
    requested = stages if bits == 168 else stages[: bits + 1]
    for name, mismatch in requested:
        solver = z3.SolverFor("QF_BV")
        solver.set(timeout=timeout_ms)
        solver.add(mismatch)
        begin = time.monotonic()
        result = solver.check()
        row = {
            "stage": name,
            "result": str(result),
            "proved": result == z3.unsat,
            "elapsed_seconds": round(time.monotonic() - begin, 6),
        }
        if result == z3.unknown:
            row["reason"] = solver.reason_unknown()
        results.append(row)
        if progress:
            print(json.dumps(row), file=sys.stderr, flush=True)
        if result != z3.unsat:
            break
    return {
        "scope": "Monolith3 virtual span: boundary=L bit 0, payload=(L>>1) mod 2^168; decoded doubled-pair equality modulo 2^168",
        "source_sha256": hashlib.sha256(Path(monolith3.__file__).read_bytes()).hexdigest(),
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "z3_version": z3.get_version_string(),
        "translation_controls": 8,
        "backend": "shared local integer carry columns (four-bit exact bounded encoding)",
        "solver_budget_per_stage_ms": timeout_ms,
        "requested_payload_bits": bits,
        "checked_payload_bits": sum(row["proved"] for row in results[1:169]),
        "wrap_balance_bound_proved": len(results) >= 170 and results[169]["proved"],
        "plain_truncation_proved": len(results) == 171 and results[170]["proved"],
        "full_proof": bits == 168 and len(results) == 171 and all(row["proved"] for row in results),
        "stages": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--bits", type=int, default=168)
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args()
    report = prove(args.timeout_ms, args.bits, args.progress)
    print(json.dumps(report, indent=2))
    if not all(row["proved"] for row in report["stages"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
