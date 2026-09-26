"""Prove individual decoded Monolith3/6 spans and both Monolith5 streams.

Carry-save formulas are checked against generated AST bits, not fitted samples.
The first pair span's top bit requires the reachable upper encoding invariant;
all other pair bits and every packed-stream bit are unconditional uint32 proofs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
import time
from pathlib import Path
from typing import Any

from s7commplus.session_auth.family0._generated import monolith5
from tools.prove_monolith4_span_identity import boolean_backend, symbolic_source
from tools.prove_monolith6_span_identity import symbolic_pair
from tools.prove_monolith_setup_invariant import UPPER_ZERO_TRIPLES, allowed_triple
from tools.recover_monolith4_span_identity import input_gate_diagram, normalized_terms, output_bit_diagram
from tools.transform7_setup_integer import H


def symbolic_packing() -> tuple[Any, Any, list[Any], list[list[Any]], list[list[Any]]]:
    z3, source, words_out = symbolic_source(5)
    backend = boolean_backend(z3, len(source))
    boundary, terms = normalized_terms()
    inputs = [[] for _ in range(3)]
    for term in terms:
        for span in range(3):
            gate = input_gate_diagram(term, span, backend)
            inputs[span].append(z3.Not(gate) if term.weight < 0 else gate)
    boundaries = [input_gate_diagram(boundary, span, backend) for span in range(3)]
    outputs = [
        [
            z3.BoolVal(bool(value)) if type(value) is int else value
            for k in range(168)
            for value in [output_bit_diagram(span * 6 + k // 28, k % 28 + 2, backend, 5)]
        ]
        for span in range(2)
    ]
    rng = random.Random(0xC5A5)
    for _ in range(8):
        words = [rng.getrandbits(32) for _ in source]
        native = bytearray(48)
        monolith5.execute(native, struct.pack("<54I", *words))
        bindings = [(variable, z3.BitVecVal(word, 32)) for variable, word in zip(source, words)]
        actual = [z3.simplify(z3.substitute(value, *bindings)).as_long() for value in words_out]
        if actual != list(struct.unpack("<12I", native)):
            raise AssertionError("fixed-width packing compiler differs from generated runtime")
        bit_bindings = [
            (variable, z3.BoolVal(bool(words[word] >> bit & 1))) for variable, (word, bit) in zip(backend.variables, backend.refs)
        ]
        for span in range(2):
            for k, bit in enumerate(outputs[span]):
                actual_bit = z3.simplify(z3.substitute(bit, *bit_bindings))
                expected = (
                    int.from_bytes(native[span * 24 + (k // 28) * 4 : span * 24 + (k // 28) * 4 + 4], "little") >> (k % 28 + 2)
                    & 1
                )
                if not (z3.is_true(actual_bit) or z3.is_false(actual_bit)) or z3.is_true(actual_bit) != bool(expected):
                    raise AssertionError("demanded packing compiler differs from generated runtime")
    return z3, backend, boundaries, inputs, outputs


def equations(number: int) -> tuple[Any, list[tuple[str, Any, list[Any]]]]:
    if number not in (3, 5, 6):
        raise ValueError("unsupported carry-save kernel")
    if number == 5:
        z3, backend, hs, inputs, outputs = symbolic_packing()
        boundaries_out = []
    else:
        z3, backend, hs, boundaries_out, inputs, outputs = symbolic_pair(number)

    def xor3(bits: list[Any]) -> Any:
        return z3.Xor(z3.Xor(bits[0], bits[1]), bits[2])

    def majority(bits: list[Any]) -> Any:
        a, b, c = bits
        return z3.Or(z3.And(a, b), z3.And(a, c), z3.And(b, c))

    columns = [[bits[k] for bits in inputs] for k in range(168)]
    parity_h, majority_h = xor3(hs), majority(hs)
    sums, carries = [], []
    for k in range(168):
        operands = [
            xor3(columns[k]),
            parity_h if H >> k & 1 else z3.BoolVal(False),
            majority(columns[k - 1]) if k else majority_h,
        ]
        sums.append(xor3(operands))
        carries.append(majority(operands))
    rows = []
    if number == 5:
        for k in range(168):
            rows.append((f"stream_0_bit_{k}", z3.Xor(outputs[0][k], sums[k]), []))
            rows.append((f"stream_1_bit_{k}", z3.Xor(outputs[1][k], carries[k - 1] if k else z3.BoolVal(False)), []))
        return z3, rows
    rows.extend([("boundary_0", z3.Xor(boundaries_out[0], sums[0]), []), ("boundary_1_zero", boundaries_out[1], [])])
    for k in range(167):
        rows.append((f"span_0_bit_{k}", z3.Xor(outputs[0][k], sums[k + 1]), []))
    for k in range(168):
        rows.append((f"span_1_bit_{k}", z3.Xor(outputs[1][k], carries[k]), []))
    assumptions = []
    for span in range(2 if number == 3 else 3):
        assumptions.extend(z3.Not(bit) for bit in inputs[span][166:])
        for bit, allowed in enumerate(UPPER_ZERO_TRIPLES, 9):
            values = [backend.variables[backend.ref_index[span * 18 + 15 + member, bit]] for member in range(3)]
            assumptions.append(allowed_triple(z3, values, allowed))
    if number == 3:
        assumptions.extend(z3.Not(backend.variables[backend.ref_index[36 + k // 32, k % 32]]) for k in range(162, 192))
    rows.append(("span_0_bit_167_zero_under_setup_invariant", outputs[0][167], assumptions))
    return z3, rows


def prove(timeout_ms: int = 10000, progress: bool = False) -> dict[str, Any]:
    if timeout_ms <= 0:
        raise ValueError("expected positive solver timeout")
    rows = []
    for number in (3, 5, 6):
        z3, queries = equations(number)
        for stage, mismatch, assumptions in queries:
            solver = z3.Tactic("sat").solver()
            solver.set(timeout=timeout_ms)
            solver.add(*assumptions, mismatch)
            start = time.monotonic()
            result = solver.check()
            row = {
                "monolith": number,
                "stage": stage,
                "conditional": bool(assumptions),
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
        "scope": "individual decoded carry-save spans/streams; pair span0 top bit conditional on the proved setup invariant",
        "source_sha256": {
            f"monolith{number}.py": hashlib.sha256((folder / f"monolith{number}.py").read_bytes()).hexdigest()
            for number in (3, 5, 6)
        },
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "upper_zero_triples": UPPER_ZERO_TRIPLES,
        "z3_version": z3.get_version_string(),
        "translation_controls_per_kernel": 8,
        "expected_stages": 1012,
        "solver_budget_per_stage_ms": timeout_ms,
        "full_proof": len(rows) == 1012 and all(row["proved"] for row in rows),
        "stages": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--progress", action="store_true")
    parser.add_argument(
        "--summary", action="store_true", help="omit stage rows from final JSON; --progress still emits every row"
    )
    args = parser.parse_args()
    report = prove(args.timeout_ms, args.progress)
    if args.summary:
        report = {name: value for name, value in report.items() if name != "stages"}
    print(json.dumps(report, indent=2))
    if not report["full_proof"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
