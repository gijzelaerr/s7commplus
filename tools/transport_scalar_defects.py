"""Lift observed carry defects through SSA into symbolic coordinate corrections.

Synthetic checkout analysis only. Polynomials use independent variables for
the observed operation corrections, preserving nonlinear interactions exactly.
The defect locations/predicates are observed, NOT recovered symbolically for
all inputs. No runtime replacement or whole-pipeline proof is claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from math import gcd
from pathlib import Path
from typing import cast

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import recover_scalar_curve as curve
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Operand
from tools.recover_scalar_encodings import coefficients, initial_encoder, inverse_encoder, recover_all, scalar_xor_mask
from tools.recover_scalar_shadow import MODULUS, Polynomial, add, evaluate, multiply, substitute
from tools.recover_transform12_phase1 import recover as stages
from tools.scalar_ladder_model import step
from tools.trace_scalar_defects import Defect, evaluate_stage
from tools.transform7_setup_integer import model as setup


@dataclass(frozen=True)
class Transport:
    index: int
    bit: int
    events: tuple[Defect, ...]
    outputs: dict[int, Polynomial]
    coordinates: tuple[Polynomial, ...]
    peak_terms: int


def lift(index: int, state: dict[int, int], bit: int, events: tuple[Defect, ...]) -> Transport:
    """Interpret complete equations with an independent variable per defect."""
    if type(index) is not int or not 0 <= index < 160:
        raise ValueError("stage index must be 0..159")
    stage = stages()[index]
    if bit not in (0, 1) or set(state) != set(stage.inputs):
        raise ValueError("stage input layout or branch mismatch")
    for value in state.values():
        exact.encode(value)
    if len(events) > 8:
        raise ValueError("symbolic transport is limited to eight local defects")
    indexes = [event.tape_index for event in events]
    if len(set(indexes)) != len(indexes) or any(event.stage != index or event.branch != bit for event in events):
        raise ValueError("defect locations must be unique and match this branch")
    instructions = {i.tape_index: i for i in stage.choices[bit].instructions}
    if any(location not in instructions for location in indexes):
        raise ValueError("defect location outside the live source program")
    if any(
        event.operation != instructions[event.tape_index].operation or event.operation not in ("add", "subtract")
        for event in events
    ):
        raise ValueError("defect operation differs from the source")
    width = len(events)
    variables = curve.variables(width)
    injections = dict(zip(indexes, variables))
    values: dict[int, Polynomial] = {}

    def constant(value: int) -> Polynomial:
        value %= MODULUS
        return {(0,) * width: value} if value else {}

    def resolve(operand: Operand) -> Polynomial:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return constant(state[operand.index])
        offset = operand.index * 24
        return constant(exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]))

    peak = 0
    for instruction in stage.choices[bit].instructions:
        a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
        if instruction.operation in ("add", "subtract"):
            result = add(a, b, -1 if instruction.operation == "subtract" else 1)
        elif instruction.operation in ("multiply", "square"):
            result = multiply(a, b, 4096)
        else:
            raise ValueError("unsupported source operation")
        if instruction.tape_index in injections:
            result = add(result, injections[instruction.tape_index])
        if len(result) > 4096:
            raise ValueError("symbolic transport exceeds the term limit")
        peak = max(peak, len(result))
        values[instruction.value] = result
    outputs = {s: resolve(o) for s, o in stage.choices[bit].outputs}
    coordinates: tuple[Polynomial, ...]
    if index == 0:
        coordinates = ()  # The conditional setup/first-stage domain is separate.
    elif index == 159:
        coordinates = outputs[87], outputs[5]
    else:
        row = recover_all()[index - 1]
        slots = tuple(s for s in stage.outputs if s != 94)
        coordinates = tuple(substitute(p, tuple(outputs[s] for s in slots), width) for p in row.decoder)
    return Transport(index, bit, events, outputs, coordinates, peak)


@lru_cache(maxsize=159)
def entry_decoder(index: int) -> tuple[tuple[int, ...], tuple[Polynomial, ...]]:
    if not 1 <= index <= 159:
        raise ValueError("entry coordinates require stage 1..159")
    if index > 1:
        row = recover_all()[index - 2]
        return tuple(s for s in sorted(row.outputs) if s != 94), row.decoder
    encoder = initial_encoder()
    slots = tuple(s for s in sorted(encoder) if s != 94)
    stripped = tuple({powers[:4]: value for powers, value in encoder[s].items()} for s in slots)
    if any(powers[4] for s in slots for powers in encoder[s]):
        raise AssertionError("entry encoder unexpectedly consumes t")
    inverse = inverse_encoder(stripped)
    decoder = tuple({powers[:4]: value for powers, value in poly.items()} for poly in inverse)
    return slots, decoder


def decode_entry(index: int, state: dict[int, int]) -> tuple[int, ...]:
    slots, decoder = entry_decoder(index)
    return tuple(evaluate(p, tuple(state[s] for s in slots)) for p in decoder)


def propagate_scales(scales: tuple[int, int], bit: int) -> tuple[int, int]:
    """Degree-four doubling and degree-(2,2) addition homogeneity."""
    if bit not in (0, 1):
        raise ValueError("ladder bit must be zero or one")
    a, b = scales
    addition = a * a * b * b % MODULUS
    return (pow(a, 4, MODULUS), addition) if bit == 0 else (addition, pow(b, 4, MODULUS))


def closed_suffix_scale(local_scale: int, effective_suffix: int, remaining: int) -> int:
    """Second-point scale for a suffix starting with scales (1,local_scale).

    Conditional on no further nontrivial corrections: after m steps, with
    q=2**m and consumed effective suffix n, the exponents of local_scale are
    q*(q-n-1), q*(q-n). Effective bit e corresponds to ladder bit 1-e.
    Both branch recurrences preserve this integer identity without any
    modulus/group-order assumption or exponent reduction.
    """
    if type(remaining) is not int or not 0 <= remaining <= 160:
        raise ValueError("remaining suffix length must be 0..160")
    if type(effective_suffix) is not int or not 0 <= effective_suffix < 1 << remaining:
        raise ValueError("effective suffix does not fit its bit length")
    q = 1 << remaining
    return pow(local_scale, q * (q - effective_suffix), MODULUS)


def projective_correction(point: tuple[Polynomial, Polynomial]) -> dict[str, object]:
    """Check complete cross-product/scale identities relative to zero defects."""
    x, z = point
    width = len(next(iter(x or z), ()))
    baseline = evaluate(x, (0,) * width), evaluate(z, (0,) * width)
    cross = add(curve.scale(x, baseline[1]), curve.scale(z, baseline[0]), -1)
    scale: Polynomial | None = None
    for component, reference in zip(point, baseline):
        if gcd(reference, MODULUS) == 1:
            scale = curve.scale(component, pow(reference, -1, MODULUS))
            break
    scale_identity = scale is not None and all(
        curve.scale(scale, reference) == component for component, reference in zip(point, baseline)
    )
    return {
        "baseline": baseline,
        "cross_product": coefficients(cross),
        "cross_product_identically_zero": not cross,
        "baseline_is_zero_vector": baseline == (0, 0),
        "scale_identity": scale_identity,
        "scale": coefficients(scale) if scale_identity and scale is not None else None,
    }


def audit(index: int, state: dict[int, int], bit: int) -> dict[str, object]:
    actual, events = evaluate_stage(index, state, bit)
    transport = lift(index, state, bit, events)
    corrections = tuple(event.correction % MODULUS for event in events)
    reconstructed = {s: evaluate(p, corrections) for s, p in transport.outputs.items()}
    if reconstructed != {s: value % MODULUS for s, value in actual.items()}:
        raise AssertionError("injected defect polynomials do not reconstruct exact exit residues")
    points = [
        projective_correction((transport.coordinates[i], transport.coordinates[i + 1]))
        for i in range(0, len(transport.coordinates), 2)
    ]
    for point in points:
        scale = point["scale"]
        if scale is not None:
            scalar_poly = {tuple(row[:-1]): row[-1] for row in cast(list[list[int]], scale)}
            actual_scale = evaluate(scalar_poly, corrections)
            point["actual_scale"] = actual_scale
            point["actual_scale_is_unit"] = gcd(actual_scale, MODULUS) == 1
    entry_q = None
    baseline_matches = None
    if index > 0:
        entry = decode_entry(index, state)
        entry_q = evaluate(curve.differential_relation(), entry + (state[94],))
        flips = True if index == 159 else recover_all()[index - 1].bit_flip
        nominal = step((entry[0], entry[1]), (entry[2], entry[3]), state[94] % MODULUS, bit ^ int(flips))
        expected = nominal[1] if index == 159 else nominal[0] + nominal[1]
        baseline_matches = tuple(evaluate(p, (0,) * len(events)) for p in transport.coordinates) == expected
    return {
        "stage": index,
        "branch": bit,
        "defects": [event.tape_index for event in events],
        "corrections": corrections,
        "exit_residues_reconstructed": True,
        "peak_terms": transport.peak_terms,
        "entry_relation_residue": entry_q,
        "zero_defect_baseline_matches_compact_step": baseline_matches,
        "coordinate_polynomials": [coefficients(p) for p in transport.coordinates],
        "points": points,
    }


def reference_case(effective_scalar: int = 0, prng1: int = 0) -> dict[str, object]:
    if type(effective_scalar) is not int or not 0 <= effective_scalar < exact.LIMIT:
        raise ValueError("unsigned 160-bit effective scalar required")
    if type(prng1) is not int or not 0 <= prng1 < exact.LIMIT:
        raise ValueError("unsigned 160-bit synthetic PRNG1 required")
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    scalar = effective_scalar ^ scalar_xor_mask()
    state = dict(zip(stages()[0].inputs, setup(x, y, prng1).slots))
    rows = []
    first, second = (x * (y | 4) % MODULUS, (y | 4) % MODULUS), (pow(prng1 | 4, 2, MODULUS), 0)
    scales = (1, 1)
    verified = 0
    replay_failure = None
    noncanonical_boundaries = []
    for stage in stages():
        bit = scalar >> (159 - stage.index) & 1
        actual, events = evaluate_stage(stage.index, state, bit)
        local = None
        if events:
            local = audit(stage.index, state, bit)
            rows.append(local)
        if replay_failure is None:
            flip = False if stage.index == 0 else True if stage.index == 159 else recover_all()[stage.index - 1].bit_flip
            ladder_bit = bit ^ int(flip)
            first, second = step(first, second, x % MODULUS, ladder_bit)
            scales = propagate_scales(scales, ladder_bit)
            if local is not None:
                local_points = cast(list[dict[str, object]], local["points"])
                if not local["zero_defect_baseline_matches_compact_step"] or any(
                    not p.get("scale_identity") or not p.get("actual_scale_is_unit") for p in local_points
                ):
                    replay_failure = {
                        "stage": stage.index,
                        "reason": "observed correction is not a verified unit scale of the compact step",
                    }
                else:
                    correction_scales = tuple(cast(int, p["actual_scale"]) for p in local_points)
                    scales = (
                        scales[0] if stage.index == 159 else scales[0] * correction_scales[0] % MODULUS,
                        scales[1] * correction_scales[-1] % MODULUS,
                    )
            predicted = tuple(value * scale % MODULUS for point, scale in zip((first, second), scales) for value in point)
            expected = (
                (actual[87] % MODULUS, actual[5] % MODULUS) if stage.index == 159 else decode_entry(stage.index + 1, actual)
            )
            if replay_failure is None and (predicted[2:] if stage.index == 159 else predicted) != expected:
                replay_failure = {"stage": stage.index, "reason": "scaled compact coordinates differ from exact source boundary"}
            if replay_failure is None:
                verified += 1
        tags = {s: v // MODULUS for s, v in actual.items() if s != 94 and v >= MODULUS}
        if tags:
            noncanonical_boundaries.append({"stage": stage.index, "representative_tags": tags})
        state = actual
    predicted_tail = (second[1] * scales[1] % MODULUS, second[0] * scales[1] % MODULUS)
    tail_tags = (state[5] // MODULUS, state[87] // MODULUS)
    closed = None
    if replay_failure is None and len(rows) == 2 and [r["stage"] for r in rows] == [79, 80] and effective_scalar < 1 << 79:
        first_points = cast(list[dict[str, object]], rows[0]["points"])
        next_points = cast(list[dict[str, object]], rows[1]["points"])
        if all(p["actual_scale"] == 1 for p in first_points) and next_points[0]["actual_scale"] == 1:
            local_scale = cast(int, next_points[1]["actual_scale"])
            closed = {
                "conditional_on_verified_observed_defect_schedule": True,
                "remaining_steps": 79,
                "local_scale": local_scale,
                "integer_exponent": (1 << 79) * ((1 << 79) - effective_scalar),
                "predicted_final_scale": closed_suffix_scale(local_scale, effective_scalar, 79),
                "matches_scale_replay": closed_suffix_scale(local_scale, effective_scalar, 79) == scales[1],
            }
    root = Path(__file__).resolve().parents[1]
    source_paths = (
        "tools/transport_scalar_defects.py",
        "tools/trace_scalar_defects.py",
        "tools/transform12_residue_defects.py",
        "tools/transform12_integer_model.py",
        "tools/transform7_setup_integer.py",
        "tools/recover_transform12_phase1.py",
        "tools/decompile_transform12.py",
        "tools/recover_scalar_curve.py",
        "tools/recover_scalar_shadow.py",
        "tools/recover_scalar_encodings.py",
        "tools/scalar_ladder_model.py",
        "s7commplus/session_auth/family0/transform7.py",
        "s7commplus/session_auth/family0/_generated/data/_constants.py",
        "s7commplus/session_auth/family0/_generated/data/transform12_metadata.bin",
        "s7commplus/session_auth/family0/_generated/data/transform12_big_int_data.bin",
    )
    return {
        "scope": "symbolic transport at observed synthetic defect sites; not global predicate recovery or exact-byte rewrite",
        "effective_scalar": effective_scalar,
        "prng1": prng1,
        "stages": rows,
        "tail_actual": (state[5], state[87]),
        "scale_replay": {
            "requires_observed_source_defects_and_representative_tags": True,
            "verified_boundaries": verified,
            "failure": replay_failure,
            "final_scales": scales if replay_failure is None else None,
            "predicted_tail_residues": predicted_tail if replay_failure is None else None,
            "observed_tail_representative_tags": tail_tags,
            "tail_with_observed_tags": tuple(v + tag * MODULUS for v, tag in zip(predicted_tail, tail_tags))
            if replay_failure is None
            else None,
            "noncanonical_boundaries": noncanonical_boundaries,
            "closed_suffix_scale": closed,
        },
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in source_paths},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-scalar", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--prng1", type=lambda v: int(v, 0), default=0)
    args = parser.parse_args()
    print(json.dumps(reference_case(args.effective_scalar, args.prng1), indent=2))


if __name__ == "__main__":
    main()
