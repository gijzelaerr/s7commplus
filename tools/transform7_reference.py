"""Independent byte-exact Family0 Transform7 reference for synthetic inputs.

Connects source-proved exact setup, branch-sensitive integer recurrence, fixed
SSA tail and raw encoded-output references. No original Transform7, Transform12,
generated kernel or runtime arithmetic helper is executed. This is an analysis
oracle, not a whole-pipeline solver certificate or hardware validation. Never
feed live keys or PRNG material into checkout diagnostic commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache

from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import transform12_integer_model as arithmetic
from tools.decompile_transform12 import Program, phase2_program, trace_outputs
from tools.monolith_encoded_reference import execute as encoded
from tools.recover_transform12_formulas import FINAL_SLOTS
from tools.recover_transform12_phase1 import execute_state
from tools.transform7_setup_integer import model as setup


@dataclass(frozen=True)
class Reference:
    initial: tuple[int, ...]
    tail_inputs: tuple[int, int]
    tail_outputs: tuple[tuple[int, int], ...]
    destination: bytes


@lru_cache(maxsize=1)
def tail_program() -> Program:
    return trace_outputs(phase2_program(), list(FINAL_SLOTS))


def finalize(outputs: dict[int, int]) -> bytes:
    """Evaluate the destination-live encoded chain; slot71's pair is dead.

    PrepareFinalize is identity on canonical 160-bit packing, as used here.
    Do not substitute decoded span arithmetic: raw representation matters.
    """
    if set(outputs) != set(FINAL_SLOTS):
        raise ValueError("final chain requires exactly the four tail output slots")
    packed = {slot: arithmetic.encode(value) for slot, value in outputs.items()}
    a, b = encoded(7, packed[27], TRANSFORM7_DATA[0x90:0xD8])
    base = encoded(4, a, b)[0]
    c, d = encoded(7, packed[27], base)
    first = encoded(4, c, d)[0]
    e, f = encoded(7, packed[61], first)
    common = encoded(4, e, f)[0]
    g, h = encoded(7, packed[97], common)
    total = encoded(4, g, h)[0]
    i, j = encoded(6, total, c, d)
    left, right = encoded(6, base, i, j)
    return encoded(4, left, right)[0]


def model(prng1: bytes, prng2: bytes, source: bytes) -> Reference:
    """Return independently computed checkpoints and the complete 72-byte result."""
    if len(prng1) != 20 or len(prng2) != 20 or len(source) < 40:
        raise ValueError("reference requires two 20-byte PRNG inputs and at least 40 source bytes")
    x, y = (int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20))
    initial = setup(x, y, int.from_bytes(prng1, "little")).slots
    tail_inputs = execute_state((initial[0], initial[1], initial[2], initial[3]), int.from_bytes(prng2, "little"))
    program = tail_program()
    context = bytearray(program.context_slots * 24)
    for slot, value in zip((5, 87), tail_inputs):
        context[slot * 24 : (slot + 1) * 24] = arithmetic.encode(value)
    arithmetic.execute_program(program, context)
    outputs = {slot: arithmetic.decode(bytes(context[slot * 24 : (slot + 1) * 24])) for slot in FINAL_SLOTS}
    return Reference(initial, tail_inputs, tuple(sorted(outputs.items())), finalize(outputs))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--random-cases", type=int, choices=range(21), default=0)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x712)
    args = parser.parse_args()
    from tools.trace_transform7_tail import cases, observe

    results = []
    for case in cases(args.random_cases, args.seed):
        result = model(case.prng1, case.prng2, case.source)
        observed = observe(case)
        if result.destination != observed.destination:
            raise AssertionError(f"full Transform7 output mismatch for synthetic case {case.name}")
        results.append({"case": case.name, "destination_sha256": hashlib.sha256(result.destination).hexdigest()})
    print(
        json.dumps(
            {"scope": "independent full-output synthetic differential checks, not hardware validation", "results": results},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
