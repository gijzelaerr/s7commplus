"""Bounded caller-level comparisons for public/synthetic Family0 inputs.

The ordinary modular ladder is a deliberately conditional candidate. Its
output still uses the exact fixed tail and encoded finalizer. This diagnostic
checks whether SeedTransform's normalization and zero-nonce retry erase the
candidate's differences. It is NOT a runtime implementation, a solver proof,
or evidence of a successful PLC exchange. Patching is single-threaded; never
pass live keys, challenges, or entropy to checkout diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Literal
from unittest.mock import patch

from s7commplus.session_auth.family0 import seed_transform, transform7
from s7commplus.session_auth.family0._generated import monolith1
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from s7commplus.session_auth.keys import get_public_key
from tools import transform12_integer_model as arithmetic
from tools import transform7_reference as reference
from tools.recover_scalar_encodings import recover_all, scalar_xor_mask
from tools.recover_transform12_formulas import FINAL_SLOTS
from tools.scalar_ladder_model import model as modular_ladder

Implementation = Literal["original", "reference", "modular"]
LIMIT = 1 << 160
VENDORED_FINGERPRINT = "00:1B580465BB0551B2"
VENDORED_CARRY_R = 110530231426190989146171668128917847093029043359
VENDORED_SCALAR_FINGERPRINT = "00:0448ACCBD5A0BFD2"
VENDORED_SCALAR_R = 978004156713030480091955929130383740779312767983


@dataclass(frozen=True)
class Case:
    name: str
    public_key: bytes
    prng1: int
    selector: int
    transform1: bytes = bytes(60)

    def __post_init__(self) -> None:
        if not self.name or len(self.public_key) != 40 or len(self.transform1) != 60:
            raise ValueError("a named public/synthetic case needs exactly 40 key and 60 transform1 bytes")
        if any(type(value) is not int or not 0 <= value < LIMIT for value in (self.prng1, self.selector)):
            raise ValueError("case entropy requires two uint160 values")


@dataclass(frozen=True)
class Result:
    accepted: bool
    seed: bytes | None
    transform_outputs: tuple[bytes, ...]
    normalization_iterations: tuple[int, ...]
    entropy_requests: int


class _NonceRejected(Exception):
    """The caller requested another selector; the diagnostic supplies only one."""


def modular_output(prng1: bytes, selector: bytes, source: bytes) -> bytes:
    """Keep the actual tail/finalizer; replace only setup/scalar field semantics."""
    if len(prng1) != 20 or len(selector) != 20 or len(source) < 40:
        raise ValueError("modular candidate needs two 20-byte entropy buffers and 40 source bytes")
    x, y = (int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20))
    tail_inputs = modular_ladder(x, y, int.from_bytes(prng1, "little"), int.from_bytes(selector, "little"))
    program = reference.tail_program()
    context = bytearray(program.context_slots * 24)
    for slot, value in zip((5, 87), tail_inputs):
        context[slot * 24 : (slot + 1) * 24] = arithmetic.encode(value)
    arithmetic.execute_program(program, context)
    outputs = {slot: arithmetic.decode(bytes(context[slot * 24 : (slot + 1) * 24])) for slot in FINAL_SLOTS}
    return reference.finalize(outputs)


def first_nonce(case: Case, implementation: Implementation, normalization_limit: int = 32) -> Result:
    """Observe the first nonce only, including rejection, with bounded normalization.

    All other SeedTransform steps execute their original code. The zero check
    is not bypassed: a third entropy request records rejection instead of
    manufacturing an eventually accepted nonce. No original source is edited.
    """
    if implementation not in ("original", "reference", "modular"):
        raise ValueError("unknown diagnostic implementation")
    if type(normalization_limit) is not int or not 1 <= normalization_limit <= 32:
        raise ValueError("normalization limit must be an integer between 1 and 32")
    # Source-derived discovery must finish before Transform7 is patched.
    if implementation == "modular":
        recover_all()
        reference.tail_program()
    original = transform7.execute
    entropy = (case.prng1.to_bytes(20, "little"), case.selector.to_bytes(20, "little"))
    requests = 0
    transforms: list[bytes] = []
    normalizations: list[int] = []

    def fixed_entropy(length: int) -> bytes:
        nonlocal requests
        if length != 20:
            raise AssertionError("unexpected entropy request size")
        requests += 1
        if requests > len(entropy):
            raise _NonceRejected
        return entropy[requests - 1]

    def normalize(buffer: bytearray) -> None:
        for iteration in range(1, normalization_limit + 1):
            if monolith1.execute(buffer, bytes(buffer[:72])):
                normalizations.append(iteration)
                return
        raise ValueError("synthetic normalization exceeded the declared bound")

    def observed_transform(destination: bytearray, prng1: bytearray, selector: bytearray, source: bytes) -> None:
        if implementation == "original":
            original(destination, prng1, selector, source)
        elif implementation == "reference":
            destination[:72] = reference.model(bytes(prng1), bytes(selector), source).destination
        else:
            destination[:72] = modular_output(bytes(prng1), bytes(selector), source)
        transforms.append(bytes(destination[:72]))

    destination = bytearray(60)
    with (
        patch.object(os, "urandom", fixed_entropy),
        patch.object(seed_transform, "_monolith1_loop", normalize),
        patch.object(transform7, "execute", observed_transform),
    ):
        try:
            seed_transform.execute(destination, case.public_key, case.transform1)
        except _NonceRejected:
            return Result(False, None, tuple(transforms), tuple(normalizations), requests)
    return Result(True, bytes(destination), tuple(transforms), tuple(normalizations), requests)


def cases() -> tuple[Case, ...]:
    generator = TRANSFORM7_DATA[0xD8:0x100]
    changing = (1 << 128) + 48, 917984300236617229462155822449362250189314875415
    changing_key = b"".join(value.to_bytes(20, "little") for value in changing)
    return (
        Case("public-generator-zero-scalar", generator, 0, scalar_xor_mask()),
        Case("public-generator-unit-scalar", generator, 0, 1 ^ scalar_xor_mask()),
        Case("synthetic-on-curve-carry", changing_key, 0, 0),
        Case("vendored-key-setup-carry", get_public_key(VENDORED_FINGERPRINT), VENDORED_CARRY_R, 0),
        Case("vendored-key-scalar-carry", get_public_key(VENDORED_SCALAR_FINGERPRINT), VENDORED_SCALAR_R, 0),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(case.name for case in cases()))
    args = parser.parse_args()
    rows = []
    for case in cases():
        if args.case is not None and case.name != args.case:
            continue
        results = {name: first_nonce(case, name) for name in ("original", "reference", "modular")}
        baseline = results["original"]
        rows.append(
            {
                "case": case.name,
                "implementations": {
                    name: {
                        "accepted": result.accepted,
                        "seed_sha256": None if result.seed is None else hashlib.sha256(result.seed).hexdigest(),
                        "same_seed_and_acceptance_as_original": (result.accepted, result.seed)
                        == (baseline.accepted, baseline.seed),
                        "transform_sha256": [hashlib.sha256(value).hexdigest() for value in result.transform_outputs],
                        "normalization_iterations": result.normalization_iterations,
                        "entropy_requests": result.entropy_requests,
                    }
                    for name, result in results.items()
                },
            }
        )
    print(
        json.dumps(
            {"scope": "bounded public/synthetic first-nonce checks, NOT PLC validation or equivalence proof", "cases": rows},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
