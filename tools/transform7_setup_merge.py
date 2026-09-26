"""Exact setup-merge equations derived from six 28-bit lanes and uint carries.

Unlike the affine setup candidate, these equations are derived from source for
all six-lane payloads. Checkout-only, single-threaded capture uses synthetic
inputs; never supply live secrets.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import cast
from unittest.mock import patch

from s7commplus.session_auth.family0 import transform7
from tools import transform12_integer_model as arithmetic
from tools.recover_transform7_setup import capture_setup, recover, targeted_base_point_probe

PAYLOAD_LIMIT = 1 << 168
LOW_LIMIT = 1 << 128
LOW_MASK = LOW_LIMIT - 1
CORRECTION = 94 - LOW_LIMIT
SETUP_ADD_SLOTS = (46, 70, 48, 94)


def encode_payload(value: int) -> bytes:
    """Pack all 168 payload bits; unlike Finalize, the sixth lane has 28 bits."""
    if not 0 <= value < PAYLOAD_LIMIT:
        raise ValueError("payload must be an unsigned 168-bit integer")
    return struct.pack("<6I", *((value >> (28 * lane) & 0x0FFFFFFF) << 2 for lane in range(6)))


def decode_payload(packed: bytes) -> int:
    """Read only the lane packing that Monolith5 is proved to produce."""
    if len(packed) != 24:
        raise ValueError("payload must contain exactly 24 bytes")
    words = struct.unpack("<6I", packed)
    if any(word & ~0x3FFFFFFC for word in words):
        raise ValueError("payload contains bits outside six 28-bit lanes")
    return sum((word >> 2) << (28 * lane) for lane, word in enumerate(words))


def prepare_payload(payload: int) -> int:
    """Collapse Prepare to two bounded folds for this specific packing domain."""
    if not 0 <= payload < PAYLOAD_LIMIT:
        raise ValueError("payload must be an unsigned 168-bit integer")
    folded = (payload & arithmetic.MASK) + 47 * (payload >> 160)
    return folded if folded < arithmetic.LIMIT else folded - arithmetic.CANDIDATE_MODULUS


@dataclass(frozen=True)
class Merge:
    first_payload: int
    second_payload: int
    first_prepared: int
    second_prepared: int
    total: int
    lost_carry: bool
    result: int

    @property
    def ideal_residue(self) -> int:
        return (self.first_payload + self.second_payload) % arithmetic.CANDIDATE_MODULUS

    @property
    def residue_correction(self) -> int:
        return CORRECTION if self.lost_carry else 0


def merge(first: int, second: int) -> Merge:
    """Return the exact representative and explicit modular compatibility correction."""
    a, b = prepare_payload(first), prepare_payload(second)
    total = a + b
    lost_carry = total >= arithmetic.LIMIT and (total & LOW_MASK) >= LOW_LIMIT - 47
    result = total
    if total >= arithmetic.LIMIT:
        result = total - arithmetic.LIMIT + 47
        if lost_carry:
            result += CORRECTION
    return Merge(first, second, a, b, total, lost_carry, result)


def capture_merges(x: int, y: int, r: int) -> tuple[tuple[int, Merge], ...]:
    """Observe the four real setup additions and verify every derived output byte."""
    original = cast("Callable[[bytearray | memoryview, bytes, bytes], None]", getattr(transform7, "big_int_addition"))
    captured: list[tuple[int, Merge]] = []

    def observe(destination: bytearray | memoryview, first: bytes, second: bytes) -> None:
        if len(captured) >= 4:
            raise ValueError("unexpected additional setup merge")
        modeled = merge(decode_payload(bytes(first[:24])), decode_payload(bytes(second[:24])))
        original(destination, first, second)
        if bytes(destination[:24]) != arithmetic.encode(modeled.result):
            raise AssertionError("derived merge disagrees with the real setup addition")
        captured.append((SETUP_ADD_SLOTS[len(captured)], modeled))

    with patch.object(transform7, "big_int_addition", observe):
        capture_setup(x, y, r)
    if len(captured) != 4:
        raise ValueError("expected all four setup merges")
    return tuple(captured)


def main() -> None:
    inputs = targeted_base_point_probe()
    candidate = dict(zip((46, 48, 70), recover().encode(*inputs)))
    candidate[94] = inputs[0] % arithmetic.CANDIDATE_MODULUS
    observed = capture_merges(*inputs)
    print(
        json.dumps(
            {
                "scope": "exact six-lane merge derivation; affine setup remains a candidate",
                "carry_condition": "S >= 2^160 and (S mod 2^128) >= 2^128 - 47",
                "residue_correction_when_true": CORRECTION,
                "targeted_base_point_merges": [
                    {
                        "slot": slot,
                        **asdict(value),
                        "ideal_matches_affine_candidate": value.ideal_residue == candidate[slot],
                        "corrected_residue": (value.ideal_residue + value.residue_correction) % arithmetic.CANDIDATE_MODULUS,
                    }
                    for slot, value in observed
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
