"""Recover sparse polynomial scalar-stage formulas under modular-shadow semantics.

These are identities in a polynomial ring, not equivalence proofs for the
representation-sensitive compatibility arithmetic. No runtime code is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass

from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools.decompile_transform12 import Operand, Program
from tools.recover_transform12_phase1 import recover as recover_stages
from tools.transform12_integer_model import CANDIDATE_MODULUS, decode

MODULUS = CANDIDATE_MODULUS

Monomial = tuple[int, ...]
Polynomial = dict[Monomial, int]


def add(a: Polynomial, b: Polynomial, sign: int = 1) -> Polynomial:
    result = dict(a)
    for powers, coefficient in b.items():
        value = (result.get(powers, 0) + sign * coefficient) % MODULUS
        if value:
            result[powers] = value
        else:
            result.pop(powers, None)
    return result


def multiply(a: Polynomial, b: Polynomial, term_limit: int) -> Polynomial:
    if len(a) * len(b) > term_limit * term_limit:
        raise ValueError("polynomial multiplication exceeds the work limit")
    result: Polynomial = {}
    for powers, coefficient in a.items():
        for other, factor in b.items():
            key = tuple(x + y for x, y in zip(powers, other))
            value = (result.get(key, 0) + coefficient * factor) % MODULUS
            if value:
                result[key] = value
            else:
                result.pop(key, None)
    if len(result) > term_limit:
        raise ValueError("polynomial exceeds the term limit")
    return result


@dataclass(frozen=True)
class Formula:
    inputs: tuple[int, ...]
    outputs: dict[int, Polynomial]
    peak_terms: int


def recover(program: Program, inputs: tuple[int, ...], term_limit: int = 1024) -> Formula:
    if term_limit < 1 or len(set(inputs)) != len(inputs):
        raise ValueError("positive term limit and unique input slots required")
    zero = (0,) * len(inputs)
    values: dict[int, Polynomial] = {}

    def resolve(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            column = inputs.index(operand.index)
            return {tuple(int(i == column) for i in range(len(inputs))): 1}
        offset = operand.index * 24
        constant = decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % MODULUS
        return {zero: constant} if constant else {}

    peak = 0
    for instruction in program.instructions:
        a = resolve(instruction.operands[0])
        b = resolve(instruction.operands[-1])
        if instruction.operation in ("add", "subtract"):
            result = add(a, b, -1 if instruction.operation == "subtract" else 1)
        elif instruction.operation in ("multiply", "square"):
            result = multiply(a, b, term_limit)
        else:
            raise ValueError("unsupported operation")
        if len(result) > term_limit:
            raise ValueError("polynomial exceeds the term limit")
        peak = max(peak, len(result))
        values[instruction.value] = result
    return Formula(inputs, {slot: resolve(operand) for slot, operand in program.outputs}, peak)


def evaluate(polynomial: Polynomial, values: tuple[int, ...]) -> int:
    result = 0
    for powers, coefficient in polynomial.items():
        if len(powers) != len(values):
            raise ValueError("polynomial input width mismatch")
        term = coefficient
        for value, power in zip(values, powers):
            term = term * pow(value, power, MODULUS) % MODULUS
        result = (result + term) % MODULUS
    return result


def substitute(polynomial: Polynomial, inputs: tuple[Polynomial, ...], width: int, term_limit: int = 4096) -> Polynomial:
    """Compose sparse polynomials without interpolation or exponent reduction."""
    one = {(0,) * width: 1}
    cache: dict[tuple[int, int], Polynomial] = {}
    result: Polynomial = {}
    for powers, coefficient in polynomial.items():
        if len(powers) != len(inputs):
            raise ValueError("substitution input width mismatch")
        term = {(0,) * width: coefficient}
        for column, exponent in enumerate(powers):
            key = column, exponent
            if key not in cache:
                power = one
                for _ in range(exponent):
                    power = multiply(power, inputs[column], term_limit)
                cache[key] = power
            term = multiply(term, cache[key], term_limit)
        result = add(result, term)
    return result


def catalogue() -> dict[str, object]:
    """Regenerate identities for every branch; hash canonical coefficient lists."""
    rows = []
    for stage in recover_stages():
        for bit, program in enumerate(stage.choices):
            formula = recover(program, stage.inputs)
            coefficients = {
                str(slot): [[*powers, value] for powers, value in sorted(poly.items())] for slot, poly in formula.outputs.items()
            }
            rows.append(
                {
                    "stage": stage.index,
                    "branch": bit,
                    "inputs": stage.inputs,
                    "instructions": len(program.instructions),
                    "peak_terms": formula.peak_terms,
                    "outputs": {
                        str(slot): {"terms": len(poly), "degree": max((sum(powers) for powers in poly), default=0)}
                        for slot, poly in formula.outputs.items()
                    },
                    "polynomial_sha256": hashlib.sha256(
                        json.dumps(coefficients, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                }
            )
    return {
        "scope": "all 320 modular polynomial identities; NOT packed-runtime equivalence",
        "branches": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=int, choices=range(160), default=1)
    parser.add_argument("--branch", type=int, choices=(0, 1), default=0)
    parser.add_argument("--term-limit", type=int, default=1024)
    parser.add_argument("--formulas", action="store_true")
    parser.add_argument("--catalogue", action="store_true")
    args = parser.parse_args()
    if args.catalogue:
        print(json.dumps(catalogue(), indent=2))
        return
    stage = recover_stages()[args.stage]
    formula = recover(stage.choices[args.branch], stage.inputs, args.term_limit)
    report: dict[str, object] = {
        "scope": "modular polynomial identities; NOT packed-runtime equivalence",
        "stage": args.stage,
        "branch": args.branch,
        "inputs": formula.inputs,
        "instructions": len(stage.choices[args.branch].instructions),
        "peak_terms": formula.peak_terms,
        "outputs": {
            str(slot): {"terms": len(poly), "degree": max((sum(powers) for powers in poly), default=0)}
            for slot, poly in formula.outputs.items()
        },
    }
    if args.formulas:
        report["formulas"] = {
            str(slot): [[*powers, value] for powers, value in sorted(poly.items())] for slot, poly in formula.outputs.items()
        }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
