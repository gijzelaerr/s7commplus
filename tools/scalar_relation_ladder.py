"""Executable translation checks for the existing compact Q-aware recurrence.

Source coefficient verification establishes two canonical intermediate-stage
variants: ordinary ladder or Q added to the doubled numerator. No Q=0,
curve-membership, division or prime-modulus assumption. These are field-only
identities: actual compatibility carry corrections and lift bits remain separate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from tools import recover_scalar_curve as curve
from tools.recover_scalar_encodings import Encoding, recover_all
from tools.recover_scalar_shadow import MODULUS, Polynomial, add, evaluate, multiply, recover, substitute
from tools.recover_transform12_phase1 import recover as stages
from tools.recover_scalar_relation_terms import generalized_step as step

P = MODULUS
B = curve.CURVE_B
Point = tuple[int, int]


@dataclass(frozen=True)
class Policy:
    stage: int
    bit_flip: bool
    relation_on_double: bool


class Ring:
    """Execute the actual numerical formulas on exact coefficient objects."""

    def __init__(self, poly: Polynomial) -> None:
        self.poly = poly

    def other(self, value: object) -> Polynomial:
        if isinstance(value, Ring):
            return value.poly
        if type(value) is int:
            return {(0,) * 5: value % P} if value % P else {}
        raise ValueError("unsupported relation-formula value")

    def __add__(self, other: object) -> Ring:
        return Ring(add(self.poly, self.other(other)))

    __radd__ = __add__

    def __sub__(self, other: object) -> Ring:
        return Ring(add(self.poly, self.other(other), -1))

    def __rsub__(self, other: object) -> Ring:
        return Ring(add(self.other(other), self.poly, -1))

    def __mul__(self, other: object) -> Ring:
        return Ring(multiply(self.poly, self.other(other), 16384))

    __rmul__ = __mul__

    def __pow__(self, exponent: int) -> Ring:
        if type(exponent) is not int or not 0 <= exponent <= 8:
            raise ValueError("bounded nonnegative polynomial powers required")
        result = Ring({(0,) * 5: 1})
        for _ in range(exponent):
            result = result * self
        return result

    def __mod__(self, modulus: int) -> Ring:
        if modulus != P:
            raise ValueError("relation formulas must use the source modulus")
        return self

    def __bool__(self) -> bool:
        raise ValueError("polynomial may not choose a sampled branch")


def symbolic_step(bit: int, relation_on_double: bool) -> tuple[Polynomial, ...]:
    x, z, u, v, t = (Ring(poly) for poly in curve.variables(5))
    actual_formula: Any = step
    points = actual_formula((x, z), (u, v), t, bit, relation_on_double)
    return tuple(value.poly for point in points for value in point)


def raw_fields(index: int, bit: int, encoder: dict[int, Polynomial]) -> dict[int, Polynomial]:
    stage = stages()[index]
    incoming = tuple(encoder[s] for s in stage.inputs)
    # Unreduced polynomial composition: NEVER divide out Q here.
    return {s: substitute(poly, incoming, 5, 16384) for s, poly in recover(stage.choices[bit], stage.inputs).outputs.items()}


@lru_cache(maxsize=1)
def policies() -> tuple[Policy, ...]:
    """Discover either variant and recheck every unreduced source coefficient."""
    rows = []
    candidates = {(bit, mode): symbolic_step(bit, mode) for bit in (0, 1) for mode in (False, True)}
    for encoding in recover_all():
        slots = tuple(s for s in stages()[encoding.stage].outputs if s != 94)
        actual = []
        for bit in (0, 1):
            raw = raw_fields(encoding.stage, bit, encoding.inputs)
            actual.append(tuple(substitute(poly, tuple(raw[s] for s in slots), 5, 16384) for poly in encoding.decoder))
        accepted = [
            mode for mode in (False, True) if all(actual[bit] == candidates[bit ^ int(encoding.bit_flip), mode] for bit in (0, 1))
        ]
        if len(accepted) != 1:
            raise ValueError(f"stage{encoding.stage} has no unique unconditional relation-ladder policy")
        rows.append(Policy(encoding.stage, encoding.bit_flip, accepted[0]))
    final_encoder = recover_all()[-1].outputs
    for bit in (0, 1):
        raw = raw_fields(159, bit, final_encoder)
        expected = candidates[bit ^ 1, True]
        if raw[5] != expected[3] or raw[87] != expected[2]:
            raise ValueError("final source fields differ from unconditional relation ladder")
    return tuple(rows) + (Policy(159, True, True),)


def decode_entry(index: int, state: dict[int, int], encodings: tuple[Encoding, ...]) -> tuple[int, ...]:
    slots = tuple(sorted(s for s in state if s != 94))
    incoming = tuple(state[s] % P for s in slots)
    if index == 1:
        a, b, c, d = incoming
        return b, (a - d * d) % P, (c - d) % P, d, state[94] % P
    return tuple(evaluate(poly, incoming) for poly in encodings[index - 2].decoder) + (state[94] % P,)


def field_stage(index: int, state: dict[int, int], bit: int) -> dict[int, int]:
    """Source ordinary-ring outputs, NOT compatibility arithmetic outputs."""
    if type(index) is not int or not 1 <= index <= 159 or type(bit) is not int or bit not in (0, 1):
        raise ValueError("stage1..159 and branch0/1 required")
    if set(state) != set(stages()[index].inputs) or any(type(v) is not int or not 0 <= v < 1 << 160 for v in state.values()):
        raise ValueError("unsigned160 stage entry layout required")
    policy = policies()[index - 1]
    encodings = recover_all()
    x, z, u, v, t = decode_entry(index, state, encodings)
    first, second = step((x, z), (u, v), t, bit ^ int(policy.bit_flip), policy.relation_on_double)
    if index == 159:
        return {5: second[1], 87: second[0]}
    point = first + second + (t,)
    return {s: evaluate(poly, point) for s, poly in encodings[index - 1].outputs.items()}


def report() -> dict[str, object]:
    rows = policies()
    return {
        "scope": "unconditional compact field recurrence; stages1..159; no Q=0, curve or prime assumption; NOT compatibility carries/lifts",
        "intermediate_stages": 158,
        "intermediate_relation_on_double": tuple(row.stage for row in rows[:-1] if row.relation_on_double),
        "final_relation_on_double": rows[-1].relation_on_double,
        "unreduced_coordinate_identities": 158 * 8 + 4,
        "compact_variants": 2,
        "whole_runtime_equivalence": False,
        "policies": [row.__dict__ for row in rows],
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = report()
    print(json.dumps({k: v for k, v in result.items() if k != "policies"}, indent=2))


if __name__ == "__main__":
    main()
