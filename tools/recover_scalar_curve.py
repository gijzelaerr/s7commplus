"""Check short curve-shaped identities in the first two scalar stages.

Every comparison uses complete sparse polynomials, not fitted evaluations.
Stage zero assumes the conditional affine setup shadow, whose carry exception
is retained as a negative control. Stage one uses a bijective polynomial change
of coordinates on arbitrary entry residues. This is not a curve implementation,
a decoder for subsequent stages, or an exact runtime replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from math import gcd
from pathlib import Path

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA, TRANSFORM12_METADATA
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import Operand
from tools.recover_scalar_shadow import MODULUS, Polynomial, add, evaluate, multiply, recover, substitute
from tools.recover_transform12_phase1 import evaluate_stage, recover as stages
from tools.trace_transform7_setup_shadows import conditional_candidate
from tools.transform7_setup_integer import model as setup

CURVE_B = exact.decode(TRANSFORM12_BIG_INT_DATA[58 * 24 : 59 * 24]) % MODULUS


def variables(width: int) -> tuple[Polynomial, ...]:
    return tuple({tuple(int(i == column) for i in range(width)): 1} for column in range(width))


def scale(poly: Polynomial, coefficient: int) -> Polynomial:
    return {powers: value * coefficient % MODULUS for powers, value in poly.items() if value * coefficient % MODULUS}


def product(*polynomials: Polynomial) -> Polynomial:
    if not polynomials:
        raise ValueError("at least one polynomial required")
    result = polynomials[0]
    for other in polynomials[1:]:
        result = multiply(result, other, 4096)
    return result


def square(poly: Polynomial) -> Polynomial:
    return product(poly, poly)


def doubling(x: Polynomial, z: Polynomial) -> tuple[Polynomial, Polynomial]:
    """Homogeneous x-doubling numerator/denominator for y²=x³-x+b."""
    x2, z2 = square(x), square(z)
    numerator = add(add(square(x2), scale(product(x2, z2), 2)), add(scale(product(x, z, z2), -8 * CURVE_B), square(z2)))
    denominator = scale(product(z, add(add(product(x, x2), scale(product(x, z2), -1)), scale(product(z, z2), CURVE_B))), 4)
    return numerator, denominator


def first_stage() -> tuple[dict[int, Polynomial], dict[int, Polynomial]]:
    """Compose the source-derived conditional setup shadow; variables are X,Y,R.

    Y and R denote already-forced y|4 and r|4, not unconstrained runtime inputs.
    Wrapper/merge corrections are deliberately excluded, never assumed zero.
    """
    x, y, r = variables(3)
    candidate = conditional_candidate()  # Actual setup AST composition; no probes.
    inputs: list[Polynomial] = []
    for offset, row in zip(candidate.offsets, candidate.matrix):
        poly: Polynomial = {(0, 0, 0): offset} if offset else {}
        for coefficient, variable in zip(row, (x, y, r)):
            poly = add(poly, scale(variable, coefficient))
        inputs.append(poly)
    inputs.append(x)
    stage = stages()[0]
    branches = tuple(
        {slot: substitute(poly, tuple(inputs), 3) for slot, poly in recover(program, stage.inputs).outputs.items()}
        for program in stage.choices
    )
    return branches[0], branches[1]


def expected_first_stage() -> tuple[dict[int, Polynomial], dict[int, Polynomial]]:
    x, y, r = variables(3)
    one: Polynomial = {(0, 0, 0): 1}
    r4 = square(square(r))
    y4 = square(square(y))
    s = product(square(y), r4)
    numerator, denominator = doubling(x, one)
    zero = {1: add(product(y4, denominator), square(s)), 44: product(y4, numerator), 82: product(add(x, one), s), 83: s, 94: x}
    bit_one = {1: s, 44: product(x, s), 82: square(r4), 83: {}, 94: x}
    return zero, bit_one


def second_stage() -> tuple[dict[int, Polynomial], dict[int, Polynomial]]:
    """Bijective coordinates X,Z,U,V,t: slots1=Z+V²,44=X,82=U+V,83=V,94=t."""
    x, z, u, v, t = variables(5)
    inputs = add(z, square(v)), x, add(u, v), v, t
    stage = stages()[1]
    branches = tuple(
        {slot: substitute(poly, inputs, 5) for slot, poly in recover(program, stage.inputs).outputs.items()}
        for program in stage.choices
    )
    return branches[0], branches[1]


def expected_second_stage() -> tuple[dict[int, Polynomial], dict[int, Polynomial]]:
    x, z, u, v, t = variables(5)
    h2 = square(add(product(x, v), product(u, z), -1))
    addition = add(
        add(
            scale(product(add(product(x, v), product(u, z)), add(product(x, u), product(z, v), -1)), 2),
            scale(product(square(z), square(v)), 4 * CURVE_B),
        ),
        product(t, h2),
        -1,
    )
    n0, d0 = doubling(x, z)
    n1, d1 = doubling(u, v)
    correction = differential_relation()
    zero = {19: add(add(n0, square(h2)), correction), 27: d0, 31: add(addition, h2), 85: h2, 94: t}
    one = {19: add(addition, square(d1)), 27: h2, 31: add(add(n1, d1), correction), 85: d1, 94: t}
    return zero, one


def differential_relation() -> Polynomial:
    """Q=J-t*A; adjacent-point x coordinates would imply Q=0.

    Retained explicitly: zero is not assumed for arbitrary stage entry states.
    """
    x, z, u, v, t = variables(5)
    h2 = square(add(product(x, v), product(u, z), -1))
    a = add(
        add(
            scale(product(add(product(x, v), product(u, z)), add(product(x, u), product(z, v), -1)), 2),
            scale(product(square(z), square(v)), 4 * CURVE_B),
        ),
        product(t, h2),
        -1,
    )
    j = add(square(add(product(x, u), product(z, v))), scale(product(z, v, add(product(x, v), product(u, z))), 4 * CURVE_B), -1)
    return add(j, product(t, a), -1)


def first_stage_relation() -> bool:
    """Prove Q vanishes after either conditional first-stage shadow branch."""
    q = differential_relation()
    for outputs in first_stage():
        coordinates = (
            outputs[44],
            add(outputs[1], square(outputs[83]), -1),
            add(outputs[82], outputs[83], -1),
            outputs[83],
            outputs[94],
        )
        if substitute(q, coordinates, 3):
            return False
    return True


def divide_relation(polynomial: Polynomial) -> tuple[Polynomial, Polynomial]:
    """Exact one-divisor polynomial division; the leading coefficient is a unit.

    A zero remainder establishes ideal membership over Z/pZ without primality
    or treating any coordinate as an invertible field element.
    """
    divisor = differential_relation()
    leading = max(divisor)
    inverse = pow(divisor[leading], -1, MODULUS)
    pending = dict(polynomial)
    quotient: Polynomial = {}
    remainder: Polynomial = {}
    while pending:
        powers = max(pending)
        coefficient = pending[powers]
        if all(a >= b for a, b in zip(powers, leading)):
            key = tuple(a - b for a, b in zip(powers, leading))
            factor = coefficient * inverse % MODULUS
            quotient = add(quotient, {key: factor})
            pending = add(pending, multiply({key: factor}, divisor, 16384), -1)
            if len(pending) > 16384:
                raise ValueError("relation division exceeds the term limit")
        else:
            remainder[powers] = pending.pop(powers)
    return quotient, remainder


def second_stage_relation() -> list[dict[str, object]]:
    """Prove Q(next)=Q(entry)*quotient for both actual stage-one branches."""
    q = differential_relation()
    rows = []
    for bit, outputs in enumerate(second_stage()):
        coordinates = (
            add(outputs[19], square(outputs[85]), -1),
            outputs[27],
            add(outputs[31], outputs[85], -1),
            outputs[85],
            outputs[94],
        )
        derived = substitute(q, coordinates, 5, 16384)
        quotient, remainder = divide_relation(derived)
        identity_matches = add(multiply(q, quotient, 16384), remainder) == derived
        if remainder or not identity_matches:
            raise AssertionError("differential relation is not preserved by the second-stage shadow")
        rows.append(
            {
                "branch": bit,
                "relation_preserved": True,
                "expanded_relation_terms": len(derived),
                "quotient_terms": len(quotient),
                "remainder_terms": len(remainder),
                "quotient_sha256": hashlib.sha256(
                    json.dumps([[*powers, value] for powers, value in sorted(quotient.items())], separators=(",", ":")).encode()
                ).hexdigest(),
            }
        )
    return rows


@dataclass(frozen=True)
class Divergence:
    stage: int
    branch: int
    tape_index: int
    operation: str
    operands: tuple[int, ...]
    exact_result: int
    shadow_result: int


def first_divergence(stage_index: int, state: dict[int, int], bit: int) -> Divergence | None:
    stage = stages()[stage_index]
    if set(state) != set(stage.inputs) or bit not in (0, 1):
        raise ValueError("stage input layout or branch mismatch")
    for value in state.values():
        exact.encode(value)
    representatives: dict[int, int] = {}
    residues: dict[int, int] = {}

    def resolve(operand: Operand, values: dict[int, int]) -> int:
        if operand.kind == "value":
            return values[operand.index]
        if operand.kind == "input":
            return state[operand.index]
        offset = operand.index * 24
        return exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24])

    for instruction in stage.choices[bit].instructions:
        operands = tuple(resolve(operand, representatives) for operand in instruction.operands)
        modular = tuple(resolve(operand, residues) % MODULUS for operand in instruction.operands)
        a, b = modular[0], modular[-1]
        if instruction.operation == "square":
            result, shadow = exact.square(operands[0]), a * a
        else:
            result = {"add": exact.add, "subtract": exact.subtract, "multiply": exact.multiply}[instruction.operation](*operands)
            shadow = a + b if instruction.operation == "add" else (a - b if instruction.operation == "subtract" else a * b)
        shadow %= MODULUS
        if result % MODULUS != shadow:
            return Divergence(stage_index, bit, instruction.tape_index, instruction.operation, operands, result, shadow)
        representatives[instruction.value], residues[instruction.value] = result, shadow
    return None


def reachable_counterexample() -> dict[str, object]:
    """Accepted synthetic Transform7 inputs; no assertion that this is a public-key point."""
    x = (1 << 128) + 48
    initial = setup(x, 0, 0).slots
    state = dict(zip(stages()[0].inputs, initial))
    state = evaluate_stage(stages()[0], state, 0)
    divergence = first_divergence(1, state, 0)
    if divergence is None:
        raise AssertionError("reachable carry counterexample disappeared")
    formula = recover(stages()[1].choices[0], stages()[1].inputs)
    actual = evaluate_stage(stages()[1], state, 0)
    divergent_outputs = [
        slot
        for slot, poly in formula.outputs.items()
        if evaluate(poly, tuple(state[s] for s in formula.inputs)) != actual[slot] % MODULUS
    ]
    return {
        "scope": "reachable from accepted synthetic API inputs; not an on-curve/vendored-key witness",
        "source_x": x,
        "source_y": 0,
        "prng1": 0,
        "scalar_prefix": [0, 0],
        "first_divergence": asdict(divergence),
        "divergent_live_outputs": divergent_outputs,
    }


def report() -> dict[str, object]:
    first, second = first_stage(), second_stage()
    first_matches = first == expected_first_stage()
    second_matches = second == expected_second_stage()
    first_relation_matches = first_stage_relation()
    if not first_matches or not second_matches or not first_relation_matches:
        raise AssertionError("recovered polynomial differs from the manual curve-shaped identity")
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    return {
        "scope": "complete polynomial identities for stages 0/1; NOT exact-runtime curve equivalence",
        "modulus": MODULUS,
        "curve_a": -1,
        "curve_b": CURVE_B,
        "discriminant_is_unit": gcd(4 * (-1) ** 3 + 27 * CURVE_B**2, MODULUS) == 1,
        "unmodified_reference_base_point_on_curve": (y * y - x**3 + x - CURVE_B) % MODULUS == 0,
        "first_stage_matches": first_matches,
        "second_stage_matches": second_matches,
        "differential_relation_zero_after_either_first_shadow_branch": first_relation_matches,
        "second_stage_relation_preservation": second_stage_relation(),
        "whole_pipeline_equivalence": False,
        "source_sha256": {
            name: hashlib.sha256(value).hexdigest()
            for name, value in (
                ("transform12_metadata.bin", TRANSFORM12_METADATA),
                ("transform12_big_int_data.bin", TRANSFORM12_BIG_INT_DATA),
                ("transform7_data.bin", TRANSFORM7_DATA),
            )
        },
        "tool_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "recover_scalar_shadow.py",
                "recover_scalar_curve.py",
                "recover_transform12_phase1.py",
                "trace_transform7_setup_shadows.py",
            )
        },
        "counterexample": reachable_counterexample(),
    }


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(report(), indent=2))


if __name__ == "__main__":
    main()
