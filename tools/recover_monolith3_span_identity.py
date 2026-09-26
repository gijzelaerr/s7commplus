"""Monolith3's virtual input span and exact decoded quarter-input correction.

Checks actual output pairs, not an input-only encoded replacement. Never supply
live secrets; the bundled witness and main command use synthetic sources only.
"""

from __future__ import annotations

import json
import random
import struct
from collections import Counter
from dataclasses import asdict, dataclass

from s7commplus.session_auth.family0._generated import monolith3
from tools.recover_monolith4_span_identity import normalized_span
from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.recover_monolith6_span_identity import H, Relation, normalized_relation

PLAIN_LIMIT = 1 << 170


@dataclass(frozen=True)
class PlainRelation:
    encoded_inputs: tuple[tuple[int, int], ...]
    plain_original: int
    plain_effective: int
    pair: Relation

    @property
    def wrap_balance(self) -> int:
        return self.pair.wrap_balance - (self.plain_effective >> 169)

    @property
    def input_shadow(self) -> int:
        return sum(b + H * h for b, h in self.encoded_inputs) % P

    @property
    def output_shadow(self) -> int:
        return self.pair.output_shadow

    @property
    def corrected_shadow(self) -> int:
        return (H * self.input_shadow + H * H * self.plain_effective + (MODULUS // 2 % P) * self.wrap_balance) % P

    @property
    def full_target(self) -> int:
        return self.pair.target + MODULUS * (self.plain_effective >> 169)


def relation(source: bytes, destination: bytes) -> PlainRelation:
    if len(source) != 168 or len(destination) != 144:
        raise ValueError("expected 168 source bytes and 144 destination bytes")
    inputs = tuple(normalized_span(struct.unpack("<18I", source[i * 72 : (i + 1) * 72])) for i in range(2))
    outputs = tuple(normalized_span(struct.unpack("<18I", destination[i * 72 : (i + 1) * 72])) for i in range(2))
    original = int.from_bytes(source[144:], "little")
    effective = original & (PLAIN_LIMIT - 1)
    virtual = ((effective >> 1) % MODULUS, effective & 1)
    pair = normalized_relation(inputs + (virtual,), outputs)
    return PlainRelation(inputs, original, effective, pair)


def observe(source: bytes) -> PlainRelation:
    if len(source) != 168:
        raise ValueError("expected 168 source bytes")
    output = bytearray(144)
    monolith3.execute(output, source)
    return relation(source, bytes(output))


def high_bit_witness() -> tuple[PlainRelation, PlainRelation]:
    words = [0] * 42
    before = observe(struct.pack("<42I", *words))
    words[17] = 1 << 9
    return before, observe(struct.pack("<42I", *words))


def main() -> None:
    rng = random.Random(0x3DEC)
    observations = [observe(rng.randbytes(168)) for _ in range(1000)]
    before, after = high_bit_witness()
    print(
        json.dumps(
            {
                "scope": "sampled Monolith3 decoded quarter-input relation; wrap balance uses actual outputs; source proof is separate",
                "cases": len(observations),
                "observed_full_wrap_balances": dict(Counter(value.wrap_balance for value in observations)),
                "corrected_shadow_mismatches": sum(value.output_shadow != value.corrected_shadow for value in observations),
                "high_bit_witness": {
                    "source_word": 17,
                    "source_bit": 9,
                    "decoded_inputs_equal": before.encoded_inputs == after.encoded_inputs,
                    "plain_inputs_equal": before.plain_original == after.plain_original,
                    "output_shadow_delta": (after.output_shadow - before.output_shadow) % P,
                    "before": asdict(before),
                    "after": asdict(after),
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
