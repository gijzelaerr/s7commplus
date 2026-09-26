"""Recover and check stage-specific polynomial coordinate encodings.

Discovery solves coefficient equations over the modular-shadow ring. Accepted
decoders must have an exact polynomial inverse, and source equations must match
the compact ladder modulo its explicitly retained differential relation. None
of these conditional identities replace exact runtime carry arithmetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations_with_replacement
from math import gcd
from pathlib import Path

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA, TRANSFORM12_METADATA
from s7commplus.session_auth.family0._generated.data._constants import TRANSFORM7_COUNTS_INTS, TRANSFORM7_INDEXES_INTS

from tools import recover_scalar_curve as curve
from tools.recover_scalar_shadow import MODULUS, Polynomial, add, multiply, recover, substitute
from tools.recover_transform12_phase1 import recover as stages

Vector = dict[tuple[int, tuple[int, ...]], int]


def coefficients(polynomial: Polynomial) -> list[list[int]]:
    return [[*powers, value] for powers, value in sorted(polynomial.items())]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def remainder(polynomial: Polynomial) -> Polynomial:
    return curve.divide_relation(polynomial)[1]


def canonical_outputs() -> tuple[tuple[Polynomial, ...], tuple[Polynomial, ...]]:
    x, z, u, v, t = curve.variables(5)
    n0, d0 = curve.doubling(x, z)
    n1, d1 = curve.doubling(u, v)
    outputs = curve.expected_second_stage()
    h2 = outputs[0][85]
    a = add(outputs[0][31], h2, -1)
    return (n0, d0, a, h2), (a, h2, n1, d1)


def vector(polynomials: tuple[Polynomial, Polynomial]) -> Vector:
    return {(bit, powers): value for bit, poly in enumerate(polynomials) for powers, value in poly.items()}


def vector_add(a: Vector, b: Vector, scale: int) -> Vector:
    result = dict(a)
    for key, coefficient in b.items():
        value = (result.get(key, 0) + scale * coefficient) % MODULUS
        if value:
            result[key] = value
        else:
            result.pop(key, None)
    return result


def discover_decoder(
    outputs: tuple[dict[int, Polynomial], dict[int, Polynomial]], degree: int = 2, flip: bool = False
) -> tuple[Polynomial, ...]:
    """Solve all coefficients jointly across both branches, not numeric probes."""
    slots = tuple(slot for slot in sorted(outputs[0]) if slot != 94)
    if len(slots) != 4 or set(outputs[0]) != set(outputs[1]):
        raise ValueError("decoder discovery requires four changing output slots")
    basis: list[tuple[int, ...]] = [(0,) * 4]
    for order in range(1, degree + 1):
        for columns in combinations_with_replacement(range(4), order):
            basis.append(tuple(columns.count(i) for i in range(4)))
    pivots: dict[tuple[int, tuple[int, ...]], tuple[Vector, Polynomial]] = {}

    def reduce_vector(v: Vector, recipe: Polynomial) -> tuple[Vector, Polynomial]:
        while v:
            key = max(v)
            if key not in pivots:
                break
            factor = -v[key]
            row, expression = pivots[key]
            v = vector_add(v, row, factor)
            recipe = add(recipe, {p: factor * c % MODULUS for p, c in expression.items()})
        return v, recipe

    for powers in basis:
        polynomials = []
        for bit in (0, 1):
            poly: Polynomial = {(0,) * 5: 1}
            for slot, exponent in zip(slots, powers):
                for _ in range(exponent):
                    poly = remainder(multiply(poly, outputs[bit][slot], 16384))
            polynomials.append(poly)
        v, recipe = reduce_vector(vector((polynomials[0], polynomials[1])), {powers: 1})
        if not v:
            continue
        key = max(v)
        if gcd(v[key], MODULUS) != 1:
            raise ValueError("non-unit coefficient pivot; no field assumption permitted")
        inverse = pow(v[key], -1, MODULUS)
        pivots[key] = ({k: c * inverse % MODULUS for k, c in v.items()}, {p: c * inverse % MODULUS for p, c in recipe.items()})
    targets = canonical_outputs()
    if flip:
        targets = targets[::-1]
    decoders = []
    for index in range(4):
        v, recipe = reduce_vector(vector((remainder(targets[0][index]), remainder(targets[1][index]))), {})
        if v:
            raise ValueError(f"no degree-{degree} decoder for coordinate {index}")
        decoders.append({p: -c % MODULUS for p, c in recipe.items()})
    return tuple(decoders)


def inverse_encoder(decoder: tuple[Polynomial, ...]) -> tuple[Polynomial, ...]:
    """Invert only polynomial maps with constant-unit linear elimination pivots."""
    if len(decoder) != 4:
        raise ValueError("four decoder coordinates required")
    variables = curve.variables(9)
    equations = [add(substitute(poly, variables[:4], 9), variables[4 + i], -1) for i, poly in enumerate(decoder)]
    unresolved = set(range(4))
    solutions: dict[int, Polynomial] = {}
    while unresolved:
        pivot = None
        for row, polynomial in enumerate(equations):
            coefficients = {}
            valid = True
            for powers, value in polynomial.items():
                active = [i for i in unresolved if powers[i]]
                if not active:
                    continue
                if len(active) != 1 or sum(powers) != 1:
                    valid = False
                    break
                coefficients[active[0]] = value
            if valid:
                for column, value in coefficients.items():
                    if gcd(value, MODULUS) == 1:
                        pivot = row, column, value
                        break
            if pivot is not None:
                break
        if pivot is None:
            raise ValueError("decoder has no certified polynomial inverse by unit-linear elimination")
        row, column, value = pivot
        rhs = add(equations[row], curve.scale(variables[column], value), -1)
        expression = curve.scale(rhs, -pow(value, -1, MODULUS))
        replacements = list(variables)
        replacements[column] = expression
        equations = [substitute(poly, tuple(replacements), 9) for poly in equations]
        solutions = {i: substitute(poly, tuple(replacements), 9) for i, poly in solutions.items()}
        solutions[column] = expression
        unresolved.remove(column)
    if any(equations):
        raise ValueError("inverse leaves a nonzero coordinate equation")
    encoder = tuple({powers[4:]: value for powers, value in solutions[i].items()} for i in range(4))
    canonical = curve.variables(5)
    if any(substitute(poly, encoder, 5) != canonical[i] for i, poly in enumerate(decoder)):
        raise AssertionError("decoder/encoder composition differs from identity")
    output_variables = curve.variables(4)
    coordinates = tuple(decoder) + ({(0,) * 4: 0},)
    # Encoders cannot consume t: discovery's basis uses only changing outputs.
    if any(powers[4] for poly in encoder for powers in poly):
        raise ValueError("inverse unexpectedly consumes the fixed source coordinate")
    if any(substitute(poly, coordinates, 4) != output_variables[i] for i, poly in enumerate(encoder)):
        raise AssertionError("encoder/decoder composition differs from identity")
    return encoder


def initial_encoder() -> dict[int, Polynomial]:
    x, z, u, v, t = curve.variables(5)
    return {1: add(z, curve.square(v)), 44: x, 82: add(u, v), 83: v, 94: t}


def verify_initial() -> str:
    """Check the source-derived first stage against the generic initialization."""
    x, y, r = curve.variables(3)
    incoming: tuple[Polynomial, ...] = curve.product(x, y), y, curve.square(r), {}, x
    actual = curve.first_stage()
    for bit, coordinates in enumerate(canonical_outputs()):
        next_coordinates = tuple(substitute(p, incoming, 3) for p in coordinates) + (x,)
        expected = {s: substitute(poly, next_coordinates, 3) for s, poly in initial_encoder().items()}
        if expected != actual[bit]:
            raise AssertionError("first source stage differs from generic ladder initialization")
    if not curve.first_stage_relation():
        raise AssertionError("initial differential relation is not established")
    return digest([{str(s): coefficients(p) for s, p in outputs.items()} for outputs in actual])


def recover_stage(
    index: int, encoder: dict[int, Polynomial], degree: int = 2
) -> tuple[tuple[Polynomial, ...], dict[int, Polynomial], bool]:
    stage = stages()[index]
    if set(encoder) != set(stage.inputs):
        raise ValueError("entry encoder layout mismatch")
    inputs = tuple(encoder[s] for s in stage.inputs)
    outputs = tuple(
        {s: remainder(substitute(p, inputs, 5, 16384)) for s, p in recover(program, stage.inputs).outputs.items()}
        for program in stage.choices
    )
    try:
        decoder = discover_decoder((outputs[0], outputs[1]), degree)
        flip = False
    except ValueError:
        decoder = discover_decoder((outputs[0], outputs[1]), degree, flip=True)
        flip = True
    inverse = inverse_encoder(decoder)
    slots = tuple(s for s in stage.outputs if s != 94)
    next_encoder = dict(zip(slots, inverse))
    next_encoder[94] = curve.variables(5)[4]
    targets = canonical_outputs()
    if flip:
        targets = targets[::-1]
    for bit in (0, 1):
        for i, poly in enumerate(decoder):
            actual = substitute(poly, tuple(outputs[bit][s] for s in slots), 5, 16384)
            if remainder(add(actual, targets[bit][i], -1)):
                raise AssertionError("discovered decoder fails the complete source polynomial identity")
    return decoder, next_encoder, flip


def prove_identity(actual: Polynomial, expected: Polynomial) -> str:
    """Check ideal membership and reconstruct the full polynomial difference."""
    difference = add(actual, expected, -1)
    quotient, residual = curve.divide_relation(difference)
    if residual or multiply(curve.differential_relation(), quotient, 16384) != difference:
        raise AssertionError("complete source polynomial identity failed modulo Q")
    return digest(coefficients(quotient))


def verify_stage(index: int, encoder: dict[int, Polynomial], decoder: tuple[Polynomial, ...], flip: bool) -> list[str]:
    """Recheck the original, unreduced equations, independently of discovery."""
    stage = stages()[index]
    slots = tuple(s for s in stage.outputs if s != 94)
    inputs = tuple(encoder[s] for s in stage.inputs)
    targets = canonical_outputs()[::-1] if flip else canonical_outputs()
    hashes = []
    for bit, program in enumerate(stage.choices):
        raw = {s: substitute(p, inputs, 5, 16384) for s, p in recover(program, stage.inputs).outputs.items()}
        for coordinate, poly in enumerate(decoder):
            actual = substitute(poly, tuple(raw[s] for s in slots), 5, 16384)
            hashes.append(prove_identity(actual, targets[bit][coordinate]))
        if raw[94] != curve.variables(5)[4]:
            raise AssertionError("fixed coordinate differs from source")
    return hashes


def ladder_relation_proof() -> list[str]:
    q = curve.differential_relation()
    t = curve.variables(5)[4]
    return [prove_identity(substitute(q, coordinates + (t,), 5, 16384), {}) for coordinates in canonical_outputs()]


def verify_final(encoder: dict[int, Polynomial]) -> list[str]:
    stage = stages()[159]
    inputs = tuple(encoder[s] for s in stage.inputs)
    # The last stage uses inverted branches and retains the SECOND point.
    targets = canonical_outputs()[::-1]
    hashes = []
    for bit, program in enumerate(stage.choices):
        raw = {s: substitute(p, inputs, 5, 16384) for s, p in recover(program, stage.inputs).outputs.items()}
        if set(raw) != {5, 87}:
            raise AssertionError("final live-output layout differs from the model")
        hashes.append(prove_identity(raw[5], targets[bit][3]))
        hashes.append(prove_identity(raw[87], targets[bit][2]))
    return hashes


@dataclass(frozen=True)
class Encoding:
    stage: int
    inputs: dict[int, Polynomial]
    decoder: tuple[Polynomial, ...]
    outputs: dict[int, Polynomial]
    bit_flip: bool
    identity_quotient_sha256: tuple[str, ...]


@lru_cache(maxsize=1)
def recover_all() -> tuple[Encoding, ...]:
    """Recover all intermediate maps and verify direct source ideal identities."""
    verify_initial()
    encoder = initial_encoder()
    result = []
    for index in range(1, 159):
        decoder, next_encoder, flip = recover_stage(index, encoder)
        hashes = verify_stage(index, encoder, decoder, flip)
        result.append(Encoding(index, encoder, decoder, next_encoder, flip, tuple(hashes)))
        encoder = next_encoder
    verify_final(encoder)
    ladder_relation_proof()
    return tuple(result)


def scalar_xor_mask() -> int:
    # First bit is not inverted; last bit is inverted. Descending ladder emits
    # the second point, n=(2^160-1)-(scalar XOR branch-mask).
    branch_mask = 1 | sum(int(row.bit_flip) << (159 - row.stage) for row in recover_all())
    return ((1 << 160) - 1) ^ branch_mask


def report() -> dict[str, object]:
    records = recover_all()
    rows = [
        {
            "stage": row.stage,
            "inputs": {str(s): coefficients(p) for s, p in row.inputs.items()},
            "decoder": [coefficients(p) for p in row.decoder],
            "outputs": {str(s): coefficients(p) for s, p in row.outputs.items()},
            "bit_flip": row.bit_flip,
            "identity_quotient_sha256": row.identity_quotient_sha256,
        }
        for row in records
    ]
    return {
        "scope": "complete 160-stage modular shadow; conditional setup and Q=0, NOT exact-runtime equivalence",
        "intermediate_stages": len(rows),
        "source_coordinate_identities": sum(len(row.identity_quotient_sha256) for row in records) + 4 + 10,
        "initial_conditional_identity_sha256": verify_initial(),
        "scalar_xor_mask_hex": f"{scalar_xor_mask():040x}",
        "generic_ladder_relation_quotient_sha256": ladder_relation_proof(),
        "final_source_identity_quotient_sha256": verify_final(records[-1].outputs),
        "complete_stage_encoding_sha256": digest(rows),
        "whole_runtime_equivalence": False,
        "source_sha256": {
            "transform12_metadata.bin": hashlib.sha256(TRANSFORM12_METADATA).hexdigest(),
            "transform12_big_int_data.bin": hashlib.sha256(TRANSFORM12_BIG_INT_DATA).hexdigest(),
            "transform7_data.bin": hashlib.sha256(TRANSFORM7_DATA).hexdigest(),
            "transform7.py": hashlib.sha256(Path(transform7.__file__).read_bytes()).hexdigest(),
            "dispatch_indexes_and_counts": digest([TRANSFORM7_INDEXES_INTS, TRANSFORM7_COUNTS_INTS]),
        },
        "tool_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "recover_scalar_encodings.py",
                "recover_scalar_curve.py",
                "recover_scalar_shadow.py",
                "decompile_transform12.py",
                "recover_transform12_phase1.py",
                "trace_transform7_setup_shadows.py",
            )
        },
        "encodings": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--through-stage", type=int, choices=range(1, 159), default=158)
    parser.add_argument("--degree", type=int, choices=(2, 3, 4), default=2)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    if args.summary:
        print(json.dumps({k: v for k, v in report().items() if k != "encodings"}, indent=2))
        return
    encoder = initial_encoder()
    for index in range(1, args.through_stage + 1):
        try:
            decoder, encoder, flip = recover_stage(index, encoder, args.degree)
        except ValueError as error:
            print(json.dumps({"stage": index, "recovered": False, "reason": str(error)}), flush=True)
            raise SystemExit(1) from error
        print(
            json.dumps(
                {
                    "stage": index,
                    "recovered": True,
                    "bit_flip": flip,
                    "decoder": [[[*powers, coefficient] for powers, coefficient in sorted(poly.items())] for poly in decoder],
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
