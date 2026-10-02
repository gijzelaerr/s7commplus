"""Recover exact representation-changing shift gadgets in the fixed tail.

For47<=c<p, add(a,c)-c canonicalizes the corrected field result, whereas
subtract(a,c)+c lifts a small corrected result. Both retain an addition defect;
neither is an identity on raw representatives. Research only, no source edits.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

from tools.decompile_transform12 import Operand, Program
from tools.scalar_representative_rules import MODULUS
from tools.scalar_stage_plan import constant

P = MODULUS
LIMIT = 1 << 160
LOW = 1 << 128
CORRECTION = 94 - LOW


def canonical_carry(raw: int, c: int) -> bool:
    """Exact addition carry in the add-then-subtract macro."""
    return raw + c >= LIMIT and (raw + c) % LOW >= LOW - 47


def lifted_carry(mu: int, c: int) -> bool:
    """Exact carry after subtracting c; no input lift history is needed."""
    return mu < c and mu >= LOW and mu % LOW < 47


def near_p_carry(mu: int, n: int) -> bool:
    """c=p-n and1<=n<2**128-94: the canonicalizer needs only mu."""
    return mu >= LOW + n and (mu - n) % LOW < 47


def lift_independent_constant(c: int) -> bool:
    return c <= LOW - 47 or P - c < LOW - 94


def _validate(raw: int, c: int) -> None:
    if type(raw) is not int or not 0 <= raw < LIMIT:
        raise ValueError("uint160 raw operand required")
    if type(c) is not int or not 47 <= c < P:
        raise ValueError("canonical constant47..p-1 required")


def canonical_shift(raw: int, c: int) -> int:
    """Exactly subtract(add(raw,c),c), including exceptional residue changes."""
    _validate(raw, c)
    return (raw % P + (CORRECTION if canonical_carry(raw, c) else 0)) % P


def lifted_shift(raw: int, c: int) -> int:
    """Exactly add(subtract(raw,c),c), including exceptional residue changes."""
    _validate(raw, c)
    mu = raw % P
    result = (mu + (CORRECTION if lifted_carry(mu, c) else 0)) % P
    return result + (P if result <= 46 else 0)


def canonical_residue_shift(mu: int, c: int) -> int:
    """Canonicalizer with NO incoming lift dependency in the proved domain.

    Every recovered fixed-tail constant is in this domain. General canonical
    constants are not: callers must not erase their raw input's lift bit.
    """
    _validate(mu, c)
    if mu >= P or not lift_independent_constant(c):
        raise ValueError("canonical residue and lift-independent constant required")
    return canonical_shift(mu, c)


@dataclass(frozen=True)
class Macro:
    operation: str
    inner_value: int
    output_value: int
    operand: Operand
    constant: int


def recover(source: Program) -> tuple[Macro, ...]:
    """Identify literal source patterns, without changing shared inner values.

    A recovered record certifies a local pattern only. Consumers must preserve
    other uses of the inner value and must not reorder independent carry sites.
    Constants outside the proved domain are deliberately left untouched.
    """
    instructions = {i.value: i for i in source.instructions}
    rows = []
    for outer in source.instructions:
        if outer.operation not in ("add", "subtract"):
            continue
        operands = (outer.operands, outer.operands[::-1]) if outer.operation == "add" else (outer.operands,)
        for value, offset in operands:
            if value.kind != "value" or offset.kind != "constant":
                continue
            c = constant(offset)
            if not 47 <= c < P:
                continue
            inner = instructions[value.index]
            if outer.operation == "subtract" and inner.operation == "add" and offset in inner.operands:
                root = inner.operands[1] if inner.operands[0] == offset else inner.operands[0]
                rows.append(Macro("canonical_shift", inner.value, outer.value, root, c))
            elif outer.operation == "add" and inner.operation == "subtract" and inner.operands[-1] == offset:
                rows.append(Macro("lifted_shift", inner.value, outer.value, inner.operands[0], c))
    return tuple(rows)


def main() -> None:
    from tools.transform7_reference import tail_program

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--equations", action="store_true", help="show readable field-only formulas for the recovered patterns")
    args = parser.parse_args()
    rows = recover(tail_program())
    if args.equations:
        for row in rows:
            value = ("v" if row.operand.kind == "value" else "s" if row.operand.kind == "input" else "K") + str(row.operand.index)
            c = str(row.constant) if row.constant < 100000 else f"p-{P - row.constant}"
            operation = "canonical_residue_shift" if row.operation == "canonical_shift" else "lifted_shift"
            print(f"v{row.output_value} = {operation}(mu({value}), {c})  # inner v{row.inner_value}; preserve its other uses")
        return
    print(
        json.dumps(
            {"scope": "local exact tail shift macros; no whole-tail rewrite or proof", "macros": [asdict(row) for row in rows]},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
