"""Recover the compact source recurrence without assuming the relation Q=0.

All intermediate encoders are polynomial bijections. Direct coefficient
identities show that some stages add Q to the doubled point's numerator;
others use the ordinary ladder. This is still modular-shadow semantics,
not an exact representative or wire-equivalence claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from tools import recover_scalar_curve as curve
from tools.recover_scalar_encodings import canonical_outputs, recover_all, verify_initial
from tools.recover_scalar_shadow import MODULUS, add, substitute
from tools.recover_scalar_shadow import recover as formulas
from tools.recover_transform12_phase1 import recover as stages
from tools.scalar_ladder_model import Point, step


@lru_cache(maxsize=1)
def recover_flags() -> tuple[bool, ...]:
    """Verify complete, unreduced identities; no division by Q or sampling."""
    rows = recover_all()
    relation = curve.differential_relation()
    flags = [False]
    for row in rows:
        stage = stages()[row.stage]
        inputs = tuple(row.inputs[s] for s in stage.inputs)
        slots = tuple(s for s in stage.outputs if s != 94)
        branches = []
        for bit, program in enumerate(stage.choices):
            raw = {s: substitute(p, inputs, 5, 16384) for s, p in formulas(program, stage.inputs).outputs.items()}
            actual = tuple(substitute(p, tuple(raw[s] for s in slots), 5, 16384) for p in row.decoder)
            ladder_bit = bit ^ int(row.bit_flip)
            targets = canonical_outputs()[ladder_bit]
            doubled_numerator = 0 if ladder_bit == 0 else 2
            differences = tuple(add(a, b, -1) for a, b in zip(actual, targets))
            nonzero = differences[doubled_numerator]
            if nonzero not in ({}, relation) or any(p for i, p in enumerate(differences) if i != doubled_numerator):
                raise AssertionError("unreduced source differs from the candidate generalized ladder")
            branches.append(bool(nonzero))
        if branches[0] != branches[1]:
            raise AssertionError("Q correction depends on a branch unexpectedly")
        flags.append(branches[0])
    # The final source stage inverts branches and keeps only the second point.
    stage = stages()[159]
    inputs = tuple(rows[-1].outputs[s] for s in stage.inputs)
    final_flag = False
    for bit, program in enumerate(stage.choices):
        raw = {s: substitute(p, inputs, 5, 16384) for s, p in formulas(program, stage.inputs).outputs.items()}
        targets = canonical_outputs()[1 - bit]
        difference = add(raw[87], targets[2], -1)
        if raw[5] != targets[3] or difference not in ({}, relation) or bit == 1 and difference:
            raise AssertionError("unreduced final source differs from the candidate generalized ladder")
        if bit == 0:
            final_flag = bool(difference)
    flags.append(final_flag)
    if len(flags) != 160:
        raise AssertionError("generalized ladder stage count changed")
    return tuple(flags)


def relation_residue(first: Point, second: Point, t: int) -> int:
    x, z = first
    u, v = second
    h2 = (x * v - u * z) ** 2 % MODULUS
    a = 2 * (x * v + u * z) * (x * u - z * v) + 4 * curve.CURVE_B * z * z * v * v - t * h2
    j = (x * u + z * v) ** 2 - 4 * curve.CURVE_B * z * v * (x * v + u * z)
    return (j - t * a) % MODULUS


def generalized_step(first: Point, second: Point, t: int, bit: int, correction: bool) -> tuple[Point, Point]:
    pair = step(first, second, t, bit)
    if not correction:
        return pair
    q = relation_residue(first, second, t)
    doubled = 0 if bit == 0 else 1
    result = list(pair)
    n, z = result[doubled]
    result[doubled] = ((n + q) % MODULUS, z)
    return result[0], result[1]


def report() -> dict[str, object]:
    flags = recover_flags()
    return {
        "scope": "unreduced polynomial identities over the modular ring; Q need not vanish; NOT exact representative or wire equivalence",
        "stage_flags": flags,
        "q_correction_stages": [i for i, flag in enumerate(flags) if flag],
        "stage_flag_sha256": hashlib.sha256(bytes(flags)).hexdigest(),
        "unconditional_intermediate_and_final_coordinate_identities": 158 * 8 + 4,
        "conditional_initial_identity_sha256": verify_initial(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "recover_scalar_relation_terms.py",
                "recover_scalar_encodings.py",
                "recover_scalar_curve.py",
                "recover_scalar_shadow.py",
            )
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(report(), indent=2))


if __name__ == "__main__":
    main()
