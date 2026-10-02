"""Derive Monolith5's exact additive span identity modulo 2^168.

This is not a field decoder or a replacement for the two-stream merge: its
modulus is 2^168 and it deliberately retains an explicit boundary correction.
Input gate and position models were recovered symbolically from generated code.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

MODULUS = 1 << 168
P = (1 << 160) - 47
U32 = 0xFFFFFFFF
Key = tuple[int, int, str, tuple[int, ...], int]


@dataclass(frozen=True)
class Term:
    chunk: int
    bit: int
    gate: str
    order: tuple[int, ...]
    inversions: int
    weight: int


@dataclass(frozen=True)
class Model:
    constant: int
    terms: tuple[Term, ...]
    boundary_weight: int


def _linear_pair(constant: int, count: int, mask: int) -> tuple[int, ...]:
    """Derive the integer multilinear coefficients of A[t]+2*B[t+1]."""
    coefficients = []
    for row in range(1 << count):
        first = constant ^ (row.bit_count() & 1)
        second = sum(1 for subset in range(1 << count) if mask & (1 << subset) and row & subset == subset) % 2
        coefficients.append(first + 2 * second)
    for variable in range(count):
        for row in range(1 << count):
            if row & (1 << variable):
                coefficients[row] -= coefficients[row ^ (1 << variable)]
    if any(value for subset, value in enumerate(coefficients) if subset.bit_count() > 1):
        raise ValueError("output pair is not an integer linear combination of its lane functions")
    return coefficients[0], *(coefficients[1 << variable] for variable in range(count))


@lru_cache(maxsize=1)
def recover() -> Model:
    """Check every output pair and cancel parity/majority coefficients exactly."""
    directory = Path(__file__).parent
    positions = json.loads((directory / "monolith5_model.json").read_text())["entries"]
    gates = json.loads((directory / "monolith5_gate_model.json").read_text())["functions"]
    if len(positions) != 168:
        raise ValueError("expected 168 output payload positions")
    first = positions[0]
    if first != [1, [[0, 0, 0], [0, 1, 1]], 8, [0, 0, 2]]:
        raise ValueError("unsupported first-position boundary")
    boundary_gate = {"gate": "choose", "order": [0, 1, 2], "inversions": 0}
    for index, combine in ((0, "not_all_equal"), (2, "or3")):
        if gates[index] != {**boundary_gate, "combine": combine}:
            raise ValueError("boundary functions do not share the expected choose gate")
    # For three boundary bits: 2*OR-not_all_equal = sum-majority.
    # This also cancels the f0*f1 interaction since OR*f0=f0.
    weights: dict[Key, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    constant = 1
    for position, (a, components, mask, residual) in enumerate(positions):
        if position == 0:
            coefficients = (1, 0, -1)  # Boundary sum-majority is handled separately.
        elif position == 167:
            if residual is not None or mask != 0:
                raise ValueError("unsupported final carry")
            # Higher XOR interaction terms weigh 2^168 and vanish modulo 2^168.
            coefficients = (a, *((1 if a == 0 else -1) for _ in components))
        else:
            if residual is not None:
                raise ValueError("unexpected interior residual")
            coefficients = _linear_pair(a, len(components), mask)
        if position:
            constant += coefficients[0] << position
        for coefficient, (chunk, bit, function) in zip(coefficients[1:], components):
            if coefficient == 0:
                continue
            gate = gates[function]
            key = chunk, bit, gate["gate"], tuple(gate["order"]), gate["inversions"]
            weights[key][gate["combine"]] += coefficient << position
    boundary: Key = (0, 0, "choose", (0, 1, 2), 0)
    weights[boundary]["sum"] += 1
    weights[boundary]["majority"] -= 1
    terms = []
    boundary_weight = 0
    for key, combines in sorted(weights.items()):
        if set(combines) - {"xor3", "majority", "sum"}:
            raise ValueError("unexpected combining function")
        parity = combines.get("xor3", 0)
        remainder = combines.get("majority", 0) - 2 * parity
        if key == boundary:
            boundary_weight = remainder
            if remainder != -P:
                raise ValueError("unexpected boundary majority correction")
        elif remainder % MODULUS:
            raise ValueError("parity and majority do not cancel")
        weight = parity + combines.get("sum", 0)
        if weight:
            terms.append(Term(*key, weight))
    return Model(constant % MODULUS, tuple(terms), boundary_weight)


def local_gate(term: Term, span: Sequence[int]) -> int:
    """Evaluate one source bit's three-input gate."""
    a, b, c = (
        ((span[term.chunk * 3 + member] >> term.bit) & 1) ^ ((term.inversions >> index) & 1)
        for index, member in enumerate(term.order)
    )
    if term.gate == "choose":
        return b ^ ((a ^ b) & c)
    if term.gate == "majority":
        return (a & b) ^ (a & c) ^ (b & c)
    raise ValueError("unknown local gate")


def decode_span(span: Sequence[int]) -> int:
    """Return the exact weighted-gate decoder modulo 2^168, not modulo p."""
    if len(span) != 18 or any(not 0 <= word <= U32 for word in span):
        raise ValueError("span must contain exactly eighteen uint32 words")
    return sum(term.weight * local_gate(term, span) for term in recover().terms) % MODULUS


def combined_payload(source: Sequence[int]) -> int:
    """Predict (first_raw_stream+second_raw_stream) modulo 2^168."""
    if len(source) != 54:
        raise ValueError("source must contain exactly three encoded spans")
    spans = [source[index * 18 : (index + 1) * 18] for index in range(3)]
    boundary_bits = [((span[1] ^ ((span[0] ^ span[1]) & span[2])) & 1) for span in spans]
    majority = int(sum(boundary_bits) >= 2)
    model = recover()
    return (model.constant + sum(decode_span(span) for span in spans) + model.boundary_weight * majority) % MODULUS


def main() -> None:
    model = recover()
    print(
        json.dumps(
            {
                "semantics": "exact span identity modulo 2^168, NOT field arithmetic",
                "identity": "A+B = constant + D(span0)+D(span1)+D(span2) - p*majority(boundary_bits) (mod 2^168)",
                "model": asdict(model),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
