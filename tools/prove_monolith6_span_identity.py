"""Prove Monolith6's decoded pair identity modulo 2^168 from generated AST.

This is not unconditional field halving: wrap corrections survive modulo p.
Requires the optional development-only analysis extra; runtime is unchanged.
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

from s7commplus.session_auth.family0._generated import monolith3, monolith6
from tools.prove_monolith4_span_identity import boolean_backend, symbolic_source
from tools.recover_monolith4_span_identity import input_gate_diagram, normalized_span, normalized_terms, output_gate_diagram
from tools.recover_monolith5_span_decoder import P


def symbolic_pair(number: int = 6) -> tuple[Any, Any, list[Any], list[Any], list[list[Any]], list[list[Any]]]:
    if number not in (3, 6):
        raise ValueError("unsupported decoded-pair monolith")
    module = monolith3 if number == 3 else monolith6
    z3, source, output = symbolic_source(number)
    backend = boolean_backend(z3, len(source))
    boundary, terms = normalized_terms()
    spans = 2 if number == 3 else 3
    inputs = [[] for _ in range(spans)]
    outputs = [[] for _ in range(2)]
    for term in terms:
        for span in range(spans):
            value = input_gate_diagram(term, span, backend)
            inputs[span].append(z3.Not(value) if term.weight < 0 else value)
        for span in range(2):
            value = output_gate_diagram(term, backend, number, span)
            outputs[span].append(z3.Not(value) if term.weight < 0 else value)
    ih = [input_gate_diagram(boundary, span, backend) for span in range(spans)]
    oh = [output_gate_diagram(boundary, backend, number, span) for span in range(2)]
    if number == 3:
        ih.append(backend.variables[backend.ref_index[36, 0]])
        inputs.append([backend.variables[backend.ref_index[36 + (k + 1) // 32, (k + 1) % 32]] for k in range(168)])
    rng = random.Random(0x6A57)
    for _ in range(8):
        words = [rng.getrandbits(32) for _ in source]
        native = bytearray(144)
        module.execute(native, struct.pack(f"<{len(source)}I", *words))
        expected = struct.unpack("<36I", native)
        word_bindings = [(variable, z3.BitVecVal(word, 32)) for variable, word in zip(source, words)]
        if [z3.simplify(z3.substitute(value, *word_bindings)).as_long() for value in output] != list(expected):
            raise AssertionError("fixed-width AST translation differs from generated runtime")
        bit_bindings = [
            (variable, z3.BoolVal(bool((words[word] >> bit) & 1)))
            for variable, (word, bit) in zip(backend.variables, backend.refs)
        ]
        for span in range(2):
            value = z3.Concat(*[z3.If(bit, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)) for bit in reversed(outputs[span])])
            value = z3.Concat(z3.If(oh[span], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)), value)
            decoded = z3.simplify(z3.substitute(value, *bit_bindings)).as_long()
            payload, h = normalized_span(expected[span * 18 : (span + 1) * 18])
            if decoded != payload + (h << 168):
                raise AssertionError("demanded-bit AST translation differs from generated runtime")
    return z3, backend, ih, oh, inputs, outputs


def equations() -> tuple[Any, list[tuple[str, Any]]]:
    z3, _, ih, oh, inputs, outputs = symbolic_pair()

    def packed(bits: list[Any]) -> Any:
        return z3.Concat(*[z3.If(bit, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)) for bit in reversed(bits)])

    def number(bit: Any) -> Any:
        return z3.If(bit, z3.BitVecVal(1, 168), z3.BitVecVal(0, 168))

    parity = z3.Xor(z3.Xor(ih[0], ih[1]), ih[2])
    majority = z3.Or(z3.And(ih[0], ih[1]), z3.And(ih[0], ih[2]), z3.And(ih[1], ih[2]))
    target = sum(packed(bits) for bits in inputs) + ((P + 1) // 2) * number(parity) + number(majority)
    actual = 2 * sum(packed(bits) for bits in outputs) + sum(number(h) for h in oh)
    stages = [("boundary_exclusive", z3.And(*oh))]
    stages.extend((f"combined_bit_{bit}", z3.Extract(bit, bit, actual) != z3.Extract(bit, bit, target)) for bit in range(168))
    return z3, stages


def local_equations(number: int = 6) -> tuple[Any, list[tuple[str, Any]]]:
    """Local carry candidates; no sampled equality is assumed by the solver.

    Four-bit arithmetic cannot alias an integer mismatch: each side of a
    column equality is bounded between -4 and 6, so differences are <16.
    """
    z3, backend, ih, oh, inputs, outputs = symbolic_pair(number)

    def value(bit: Any) -> Any:
        return z3.If(bit, z3.BitVecVal(1, 4), z3.BitVecVal(0, 4))

    def majority(bits: list[Any]) -> Any:
        a, b, c = bits
        return z3.Or(z3.And(a, b), z3.And(a, c), z3.And(b, c))

    parity = z3.Xor(z3.Xor(ih[0], ih[1]), ih[2])
    columns = [[bits[k] for bits in inputs] for k in range(168)]
    counts = [sum(value(bit) for bit in column) for column in columns]
    carries = []
    for k in range(168):
        previous_majority = majority(ih) if k == 0 else majority(columns[k - 1])
        count = counts[k] + ((P + 1) // 2 >> k & 1) * value(parity) + value(previous_majority)
        carries.append(z3.LShR(count, 1))
    stages = [("boundary_exclusive", z3.And(*oh))]
    stages.append(
        ("initial_column", sum(value(bit) for bit in oh) != counts[0] + value(parity) + value(majority(ih)) - 2 * carries[0])
    )
    for k in range(1, 168):
        left = sum(value(bits[k - 1]) for bits in outputs)
        right = counts[k] + ((P + 1) // 2 >> k & 1) * value(parity) + carries[k - 1] - 2 * carries[k]
        stages.append((f"column_{k}", left != right))
    top = sum(value(bits[167]) for bits in outputs)
    stages.append(("wrap_balance_bound", z3.Or(top + 1 < carries[167], top > carries[167] + 1)))
    if number == 3:
        # The individual output encodings may use the extra plain bits. The
        # column identities already prove their cancellation through bit 166;
        # prove cancellation in the remaining top-column count separately.
        ignored = [(backend.variables[backend.ref_index[36 + k // 32, k % 32]], z3.BoolVal(False)) for k in range(170, 192)]
        stages.append(("plain_high_bits_pair_invariant", top != z3.substitute(top, *ignored)))
    return z3, stages


def prove(timeout_ms: int = 30000, bits: int = 168, progress: bool = False, local: bool = True) -> dict[str, Any]:
    if timeout_ms <= 0 or not 1 <= bits <= 168:
        raise ValueError("expected positive timeout and 1..168 bits")
    z3, stages = local_equations() if local else equations()
    results = []
    requested = stages if local and bits == 168 else stages[: bits + 1]
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
    complete = bits == 168 and len(results) == len(stages) and all(row["proved"] for row in results)
    return {
        "scope": "decoded pair: 2*(B_out0+B_out1)+h_out0+h_out1 = sum(B_in)+H*parity(h_in)+majority(h_in) modulo 2^168",
        "source_sha256": hashlib.sha256(Path(monolith6.__file__).read_bytes()).hexdigest(),
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "z3_version": z3.get_version_string(),
        "translation_controls": 8,
        "solver_budget_per_stage_ms": timeout_ms,
        "requested_payload_bits": bits,
        "checked_payload_bits": sum(row["proved"] for row in results[1:169]),
        "wrap_balance_bound_proved": local and len(results) == 170 and results[-1]["proved"],
        "backend": "local integer carry columns (four-bit exact bounded encoding)"
        if local
        else "independent decoded bitvector prefix queries",
        "full_proof": complete,
        "stages": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--bits", type=int, default=168)
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--prefix-queries", action="store_true", help="use the slower full-prefix query formulation")
    args = parser.parse_args()
    report = prove(args.timeout_ms, args.bits, args.progress, not args.prefix_queries)
    print(json.dumps(report, indent=2))
    if not all(row["proved"] for row in report["stages"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
