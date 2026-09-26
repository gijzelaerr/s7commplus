"""Recover sparse polynomial formulas for Transform12's modular shadow.

This interprets the tape in (Z/pZ)[x,y], not its exact packed arithmetic.
Polynomial identities are unconditional ring identities; identifying powers
as inverses would additionally require primality and nonzero-input proofs.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools.decompile_transform12 import Operand, Program, phase2_program, trace_outputs
from tools.transform12_integer_model import CANDIDATE_MODULUS as MODULUS
from tools.transform12_integer_model import decode
from tools import transform12_integer_model as exact

Polynomial = dict[tuple[int, int], int]
FINAL_SLOTS = (27, 61, 71, 97)


@dataclass(frozen=True)
class Divergence:
    value: int
    tape_index: int
    operation: str
    operands: tuple[int, ...]
    exact_result: int
    shadow_result: int


def first_divergence(x: int, y: int) -> Divergence | None:
    """Locate the first loss of modular congruence in the unsliced fixed tail."""
    exact.encode(x)
    exact.encode(y)
    representatives: dict[int, int] = {}
    residues: dict[int, int] = {}

    def resolve(operand: Operand, values: dict[int, int]) -> int:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return x if operand.index == 5 else y
        offset = operand.index * 24
        return decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])

    for instruction in phase2_program().instructions:
        operands = tuple(resolve(operand, representatives) for operand in instruction.operands)
        modular = tuple(resolve(operand, residues) % MODULUS for operand in instruction.operands)
        if instruction.operation == "square":
            result = exact.square(operands[0])
            shadow = modular[0] ** 2
        else:
            operation = {"add": exact.add, "subtract": exact.subtract, "multiply": exact.multiply}[instruction.operation]
            result = operation(*operands)
            a, b = modular
            shadow = a + b if instruction.operation == "add" else (a - b if instruction.operation == "subtract" else a * b)
        shadow %= MODULUS
        if result % MODULUS != shadow:
            return Divergence(instruction.value, instruction.tape_index, instruction.operation, operands, result, shadow)
        representatives[instruction.value] = result
        residues[instruction.value] = shadow
    return None


def add(a: Polynomial, b: Polynomial, sign: int = 1) -> Polynomial:
    """Add/subtract sparse polynomials, eliminating zero coefficients exactly."""
    result = dict(a)
    for monomial, coefficient in b.items():
        value = (result.get(monomial, 0) + sign * coefficient) % MODULUS
        if value:
            result[monomial] = value
        else:
            result.pop(monomial, None)
    return result


def multiply(a: Polynomial, b: Polynomial, term_limit: int) -> Polynomial:
    """Multiply without reducing exponents or assuming primality."""
    if len(a) * len(b) > term_limit * term_limit:
        raise ValueError("polynomial multiplication exceeds the work limit")
    result: Polynomial = {}
    for (x, y), coefficient in a.items():
        for (u, v), other in b.items():
            monomial = (x + u, y + v)
            value = (result.get(monomial, 0) + coefficient * other) % MODULUS
            if value:
                result[monomial] = value
            else:
                result.pop(monomial, None)
    if len(result) > term_limit:
        raise ValueError("polynomial exceeds the term limit")
    return result


def recover(program: Program | None = None, term_limit: int = 256) -> tuple[dict[int, Polynomial], int]:
    """Propagate exact symbolic polynomials through every selected equation."""
    if term_limit < 1:
        raise ValueError("term limit must be positive")
    if program is None:
        program = trace_outputs(phase2_program(), list(FINAL_SLOTS))
    values: dict[int, Polynomial] = {}
    peak = 0

    def resolve(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            if operand.index not in (5, 87):
                raise ValueError("formula recovery expects only entry slots 5 and 87")
            return {(1, 0) if operand.index == 5 else (0, 1): 1}
        offset = operand.index * 24
        constant = decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % MODULUS
        return {(0, 0): constant} if constant else {}

    for instruction in program.instructions:
        a = resolve(instruction.operands[0])
        b = resolve(instruction.operands[-1])
        if instruction.operation in ("add", "subtract"):
            result = add(a, b, -1 if instruction.operation == "subtract" else 1)
        else:
            result = multiply(a, b, term_limit)
        if len(result) > term_limit:
            raise ValueError("polynomial exceeds the term limit")
        peak = max(peak, len(result))
        values[instruction.value] = result
    return {slot: resolve(operand) for slot, operand in program.outputs}, peak


def evaluate(polynomial: Polynomial, x: int, y: int) -> int:
    """Evaluate a polynomial without expanding its enormous exponents."""
    return sum(c * pow(x, a, MODULUS) * pow(y, b, MODULUS) for (a, b), c in polynomial.items()) % MODULUS


def compact_outputs(x: int, y: int) -> dict[int, int]:
    """Evaluate the recovered short formulas, only under modular-shadow semantics."""

    def constant(row: int) -> int:
        return decode(TRANSFORM12_BIG_INT_DATA[row * 24 : (row + 1) * 24]) % MODULUS

    z = pow(x, (MODULUS - 1) // 2 - 40, MODULUS)
    inverse_like = pow(x, MODULUS - 2, MODULUS)
    out61 = z * y % MODULUS
    out97 = pow(x, 79, MODULUS) * (z + y) % MODULUS
    out27 = (constant(483) + constant(482) * inverse_like * y + constant(481) * out97 + constant(480) * out61) % MODULUS
    return {27: out27, 61: out61, 71: y % MODULUS, 97: out97}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--term-limit", type=int, default=256)
    parser.add_argument("--compare", nargs=2, type=lambda value: int(value, 0), metavar=("X", "Y"))
    args = parser.parse_args()
    outputs, peak = recover(term_limit=args.term_limit)
    if args.compare is not None:
        divergence = first_divergence(*args.compare)
        print(json.dumps({"first_divergence": asdict(divergence) if divergence else None}, indent=2))
        return
    print(
        json.dumps(
            {
                "semantics": "modular shadow, NOT packed-runtime equivalence",
                "modulus": MODULUS,
                "peak_terms": peak,
                "outputs": {str(slot): [[a, b, c] for (a, b), c in sorted(poly.items())] for slot, poly in outputs.items()},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
