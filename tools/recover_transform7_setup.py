"""Recover a candidate affine interpretation of Transform7's setup values.

Four chosen synthetic probes recover coefficients; further probes test them.
This is interpolation, NOT symbolic equivalence to the setup monoliths.
Patching is single-threaded and inputs must not contain live secrets.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from dataclasses import asdict, dataclass
from functools import lru_cache
from unittest.mock import patch

from s7commplus.session_auth.family0 import transform7, transform12
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import transform12_integer_model as arithmetic

MODULUS = arithmetic.CANDIDATE_MODULUS
SLOTS = (46, 48, 70, 94)
Matrix = tuple[tuple[int, ...], ...]


class _SetupCaptured(Exception):
    """Stop only after the real setup has completed, before scalar dispatch."""


def capture_setup(x: int, y: int, r: int) -> tuple[int, int, int, int]:
    """Run real setup on synthetic integers, without spending time on scalar multiplication."""
    for value in (x, y, r):
        arithmetic.encode(value)
    captured: list[bytes] = []

    def stop(context: bytearray, index: int, count: int) -> None:
        captured.append(bytes(context))
        raise _SetupCaptured

    try:
        with patch.object(transform12, "execute", stop):
            transform7.execute(
                bytearray(72),
                bytearray(r.to_bytes(20, "little")),
                bytearray(20),
                x.to_bytes(20, "little") + y.to_bytes(20, "little"),
            )
    except _SetupCaptured:
        pass
    if len(captured) != 1:
        raise ValueError("expected exactly one setup context")
    values = [arithmetic.decode(captured[0][slot * 24 : (slot + 1) * 24]) for slot in SLOTS]
    return values[0], values[1], values[2], values[3]


def inverse(matrix: Matrix) -> Matrix:
    """Invert using only unit pivots, without assuming that the modulus is prime."""
    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        raise ValueError("matrix must be nonempty and square")
    augmented = [[*(value % MODULUS for value in row), *(int(i == j) for j in range(size))] for i, row in enumerate(matrix)]
    for column in range(size):
        pivot = next((row for row in range(column, size) if math.gcd(augmented[row][column], MODULUS) == 1), None)
        if pivot is None:
            raise ValueError("matrix has no unit pivot")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = pow(augmented[column][column], -1, MODULUS)
        augmented[column] = [value * scale % MODULUS for value in augmented[column]]
        for row in range(size):
            if row != column:
                factor = augmented[row][column]
                augmented[row] = [(a - factor * b) % MODULUS for a, b in zip(augmented[row], augmented[column])]
    return tuple(tuple(row[size:]) for row in augmented)


@dataclass(frozen=True)
class Candidate:
    offsets: tuple[int, ...]
    matrix: Matrix

    def __post_init__(self) -> None:
        if len(self.offsets) != 3 or len(self.matrix) != 3 or any(len(row) != 3 for row in self.matrix):
            raise ValueError("candidate requires three offsets and a 3x3 matrix")

    def encode(self, x: int, y: int, r: int) -> tuple[int, ...]:
        """Predict residues; setup explicitly forces bit 2 of y and r to one."""
        for value in (x, y, r):
            arithmetic.encode(value)
        values = (x, y | 4, r | 4)
        return tuple(
            (offset + sum(a * b for a, b in zip(row, values))) % MODULUS for offset, row in zip(self.offsets, self.matrix)
        )

    def decode(self, encoded: tuple[int, ...]) -> tuple[int, ...]:
        """Invert the candidate affine map, not the unknown bit-level monoliths."""
        if len(encoded) != 3:
            raise ValueError("candidate encoding requires three values")
        centered = tuple((value - offset) % MODULUS for value, offset in zip(encoded, self.offsets))
        return tuple(sum(a * b for a, b in zip(row, centered)) % MODULUS for row in inverse(self.matrix))


@lru_cache(maxsize=1)
def recover() -> Candidate:
    """Interpolate from four fixed probes, distinct from verification inputs."""
    basis = ((1 << 140) + 123, ((1 << 139) + 321) | 4, ((1 << 138) + 555) | 4)
    baseline = capture_setup(*basis)
    columns = []
    for column in range(3):
        values = list(basis)
        values[column] += 8  # Does not alter forced bit 2.
        observed = capture_setup(*values)
        columns.append(tuple((a - b) * pow(8, -1, MODULUS) % MODULUS for a, b in zip(observed[:3], baseline[:3])))
    matrix = tuple(tuple(columns[column][row] for column in range(3)) for row in range(3))
    offsets = tuple((baseline[row] - sum(a * b for a, b in zip(matrix[row], basis))) % MODULUS for row in range(3))
    inverse(matrix)  # Validate invertibility of the interpolated map.
    return Candidate(offsets, matrix)


def targeted_base_point_probe() -> tuple[int, int, int]:
    """Construct a legal PRNG input targeting the known low-128-bit carry edge."""
    candidate = recover()
    source = TRANSFORM7_DATA[0xD8:]
    x = int.from_bytes(source[:20], "little")
    y = int.from_bytes(source[20:40], "little")
    a, b, c = candidate.matrix[0]
    r = ((1 << 128) - candidate.offsets[0] - a * x - b * (y | 4)) * pow(c, -1, MODULUS) % MODULUS
    if not r & 4:
        raise ValueError("targeted probe does not satisfy setup's forced PRNG bit")
    return x, y, r


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--random-cases", type=int, default=128)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x714)
    args = parser.parse_args()
    if args.random_cases < 0:
        parser.error("random case count cannot be negative")
    candidate = recover()
    rng = random.Random(args.seed)
    cases = [(0, 0, 0), (1, 1, 1), (2, 3, 4), (arithmetic.MASK,) * 3]
    cases.extend((rng.getrandbits(160), rng.getrandbits(160), rng.getrandbits(160)) for _ in range(args.random_cases))
    targeted = targeted_base_point_probe()
    cases.append(targeted)
    failures = []
    for index, values in enumerate(cases):
        actual = capture_setup(*values)
        if (
            tuple(value % MODULUS for value in actual[:3]) != candidate.encode(*values)
            or actual[3] % MODULUS != values[0] % MODULUS
        ):
            failures.append(index)
    print(
        json.dumps(
            {
                "scope": "interpolated candidate, NOT a symbolic equivalence proof",
                "modulus": MODULUS,
                "candidate": asdict(candidate),
                "inverse": inverse(candidate.matrix),
                "seed": args.seed,
                "verification_cases": len(cases),
                "mismatch_case_indexes": failures,
                "targeted_base_point_probe": {
                    "index": len(cases) - 1,
                    "predicted_slot46": candidate.encode(*targeted)[0],
                    "actual_slot46": capture_setup(*targeted)[0],
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
