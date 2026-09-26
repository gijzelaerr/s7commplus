"""Observe reachable Transform12 tail inputs using synthetic Transform7 runs.

Checkout-only, single-threaded instrumentation. Never feed live secrets into
this diagnostic: the CLI uses only public constants and deterministic inputs.
It patches the dispatcher temporarily, without modifying library source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass
from unittest.mock import patch

from s7commplus.session_auth import get_public_key
from s7commplus.session_auth.family0 import transform7, transform12
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from s7commplus.session_auth.family0._generated.data._constants import TRANSFORM7_COUNTS_INTS, TRANSFORM7_INDEXES_INTS
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import phase2_program, trace_outputs
from tools.recover_transform12_phase1 import INITIAL_SLOTS, execute_state
from tools.recover_transform12_formulas import FINAL_SLOTS, compact_outputs, first_divergence


@dataclass(frozen=True)
class Case:
    name: str
    prng1: bytes
    prng2: bytes
    source: bytes


@dataclass(frozen=True)
class Observation:
    entry: bytes
    exit: bytes
    destination: bytes
    dispatches: tuple[int, ...]
    phase1_entry: bytes


def observe(case: Case, inject_shadow: bool = False) -> Observation:
    """Run the real orchestration; optionally substitute only the four tail exits."""
    if len(case.prng1) != 20 or len(case.prng2) != 20 or len(case.source) < 40:
        raise ValueError("synthetic case requires two 20-byte PRNG buffers and at least 40 source bytes")
    original = transform12.execute
    entry = b""
    phase1_entry = b""
    exit_context = b""
    dispatches: list[int] = []

    def traced(context: bytearray, index: int, count: int) -> None:
        nonlocal entry, exit_context, phase1_entry
        stage = len(dispatches)
        if stage >= 249:
            raise ValueError("unexpected extra Transform12 dispatch")
        choices = [stage * 2, stage * 2 + 1]
        matches = [
            choice for choice in choices if (TRANSFORM7_INDEXES_INTS[choice], TRANSFORM7_COUNTS_INTS[choice]) == (index, count)
        ]
        if len(matches) != 1:
            raise ValueError("Transform7 dispatch does not match the expected stage")
        dispatches.append(matches[0])
        if stage == 0:
            phase1_entry = bytes(context)
        if stage == 160:
            entry = bytes(context)
        original(context, index, count)
        if stage == 248:
            if inject_shadow:
                x, y = (exact.decode(entry[slot * 24 : (slot + 1) * 24]) for slot in (5, 87))
                for slot, value in compact_outputs(x, y).items():
                    context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
            exit_context = bytes(context)

    destination = bytearray(transform7.DESTINATION_SIZE)
    with patch.object(transform12, "execute", traced):
        transform7.execute(destination, bytearray(case.prng1), bytearray(case.prng2), case.source)
    if len(dispatches) != 249 or not entry or not exit_context:
        raise ValueError("Transform7 did not execute the complete expected trace")
    return Observation(entry, exit_context, bytes(destination), tuple(dispatches), phase1_entry)


def cases(random_cases: int = 8, seed: int = 0x712) -> list[Case]:
    """Use the seed-generator base point and two bundled Family-0 public keys."""
    if random_cases < 0:
        raise ValueError("random case count cannot be negative")
    sources = {
        "base": TRANSFORM7_DATA[0xD8:],
        "s7-1500": get_public_key("00:181B7B0847D11694"),
        "s7-1200": get_public_key("01:BD426B091F08731A"),
    }
    one = (1).to_bytes(20, "little")
    high = (1 << 159).to_bytes(20, "little")
    patterns = [
        ("zero", bytes(20), bytes(20)),
        ("one", one, one),
        ("ones", b"\xff" * 20, b"\xff" * 20),
        ("high", high, high),
        ("alternating", b"\x55" * 20, b"\xaa" * 20),
    ]
    rng = random.Random(seed)
    patterns.extend((f"random-{index}", rng.randbytes(20), rng.randbytes(20)) for index in range(random_cases))
    return [Case(f"{source_name}/{name}", a, b, source) for source_name, source in sources.items() for name, a, b in patterns]


def analyze(case: Case) -> dict[str, object]:
    """Compare independent exact arithmetic, modular residues, bytes, and final output."""
    observed = observe(case)
    x, y = (exact.decode(observed.entry[slot * 24 : (slot + 1) * 24]) for slot in (5, 87))
    initial = tuple(exact.decode(observed.phase1_entry[slot * 24 : (slot + 1) * 24]) for slot in INITIAL_SLOTS)
    phase1_matches = execute_state((initial[0], initial[1], initial[2], initial[3]), int.from_bytes(case.prng2, "little")) == (
        x,
        y,
    )
    if not phase1_matches:
        raise AssertionError(f"independent first-phase recurrence disagrees for synthetic case {case.name}")
    independent = bytearray(observed.entry)
    exact.execute_program(trace_outputs(phase2_program(), list(FINAL_SLOTS)), independent)
    runtime = {slot: exact.decode(observed.exit[slot * 24 : (slot + 1) * 24]) for slot in FINAL_SLOTS}
    exact_matches = all(
        independent[slot * 24 : (slot + 1) * 24] == observed.exit[slot * 24 : (slot + 1) * 24] for slot in FINAL_SLOTS
    )
    if not exact_matches:
        raise AssertionError(f"independent exact tail disagrees for synthetic case {case.name}")
    shadow = compact_outputs(x, y)
    divergent = first_divergence(x, y)
    injected = observe(case, inject_shadow=True)
    return {
        "case": case.name,
        "phase1_model_matches": phase1_matches,
        "entry_below_p": x < exact.CANDIDATE_MODULUS and y < exact.CANDIDATE_MODULUS,
        "entry_nonzero": x != 0 and y != 0,
        "exact_model_matches": exact_matches,
        "shadow_residue_mismatch_slots": [
            slot for slot in FINAL_SLOTS if runtime[slot] % exact.CANDIDATE_MODULUS != shadow[slot]
        ],
        "shadow_packed_mismatch_slots": [slot for slot in FINAL_SLOTS if runtime[slot] != shadow[slot]],
        "first_divergence_value": divergent.value if divergent else None,
        "shadow_final_destination_matches": observed.destination == injected.destination,
        "baseline_destination_sha256": hashlib.sha256(observed.destination).hexdigest(),
    }


def summarize(results: list[dict[str, object]]) -> dict[str, object]:
    """Keep sampling success distinct from an equivalence proof."""
    return {
        "cases": len(results),
        "entry_below_p": sum(bool(result["entry_below_p"]) for result in results),
        "entry_nonzero": sum(bool(result["entry_nonzero"]) for result in results),
        "exact_model_matches": sum(bool(result["exact_model_matches"]) for result in results),
        "phase1_model_matches": sum(bool(result["phase1_model_matches"]) for result in results),
        "shadow_residue_mismatch_cases": [result["case"] for result in results if result["shadow_residue_mismatch_slots"]],
        "shadow_packed_mismatch_cases": [result["case"] for result in results if result["shadow_packed_mismatch_slots"]],
        "internal_divergence_cases": [result["case"] for result in results if result["first_divergence_value"] is not None],
        "shadow_final_destination_mismatch_cases": [
            result["case"] for result in results if not result["shadow_final_destination_matches"]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--random-cases", type=int, default=8, help="additional deterministic PRNG pairs per public source")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x712)
    parser.add_argument("--details", action="store_true", help="include per-case checks and synthetic output hashes")
    args = parser.parse_args()
    results = [analyze(case) for case in cases(args.random_cases, args.seed)]
    report = {
        "scope": "synthetic Transform7 reachability, not a proof or hardware capture",
        "seed": args.seed,
        "summary": summarize(results),
    }
    if args.details:
        report["results"] = results
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
