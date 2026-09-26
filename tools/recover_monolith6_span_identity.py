"""Track Monolith6 decoded pair halving with its explicit wrap balance.

The current decoder is not a sufficient input-only state model: an ignored
source bit can change the output pair's high payload bit. Checkout-only.
"""

from __future__ import annotations

import json
import random
import struct
from collections import Counter
from dataclasses import asdict, dataclass

from s7commplus.session_auth.family0._generated import monolith6
from tools.recover_monolith4_span_identity import normalized_span
from tools.recover_monolith5_span_decoder import MODULUS, P

H = (P + 1) // 2


def local_carries(inputs: tuple[tuple[int, int], ...]) -> tuple[int, ...]:
    """Independent integer form of the source-proved local carry rule."""
    if len(inputs) != 3 or any(not 0 <= b < MODULUS or h not in (0, 1) for b, h in inputs):
        raise ValueError("expected three normalized payload/boundary pairs")
    hs = sum(h for _, h in inputs)
    counts = [sum((b >> k) & 1 for b, _ in inputs) for k in range(168)]
    return tuple(
        (count + ((H >> k) & 1) * (hs % 2) + int((hs if k == 0 else counts[k - 1]) >= 2)) // 2 for k, count in enumerate(counts)
    )


@dataclass(frozen=True)
class Relation:
    input_spans: tuple[tuple[int, int], ...]
    output_spans: tuple[tuple[int, int], ...]
    target: int
    doubled_output: int
    wrap_balance: int
    boundary_adjustment: int

    @property
    def input_shadow(self) -> int:
        return sum(b + H * h for b, h in self.input_spans) % P

    @property
    def output_shadow(self) -> int:
        return sum(b + H * h for b, h in self.output_spans) % P

    @property
    def corrected_shadow(self) -> int:
        return (H * self.input_shadow + (MODULUS // 2 % P) * self.wrap_balance) % P

    @property
    def local_wrap_balance(self) -> int:
        return sum(b >> 167 for b, _ in self.output_spans) - local_carries(self.input_spans)[167]


def relation(source: bytes, destination: bytes) -> Relation:
    """Check the decoded identity for a supplied pair; not input-only prediction."""
    if len(source) != 216 or len(destination) != 144:
        raise ValueError("expected 216 source bytes and 144 destination bytes")
    inputs = tuple(normalized_span(struct.unpack("<18I", source[i * 72 : (i + 1) * 72])) for i in range(3))
    outputs = tuple(normalized_span(struct.unpack("<18I", destination[i * 72 : (i + 1) * 72])) for i in range(2))
    return normalized_relation(inputs, outputs)


def normalized_relation(inputs: tuple[tuple[int, int], ...], outputs: tuple[tuple[int, int], ...]) -> Relation:
    """Check a decoded three-to-two relation, including virtual input spans."""
    if len(inputs) != 3 or len(outputs) != 2 or any(not 0 <= b < MODULUS or h not in (0, 1) for b, h in inputs + outputs):
        raise ValueError("expected normalized three-input/two-output pairs")
    ih = sum(h for _, h in inputs)
    oh = sum(h for _, h in outputs)
    if oh > 1:
        raise ValueError("output boundary gates are not exclusive")
    majority = int(ih >= 2)
    target = sum(b for b, _ in inputs) + H * (ih % 2) + majority
    doubled = 2 * sum(b for b, _ in outputs) + oh
    wrap, remainder = divmod(doubled - target, MODULUS)
    if remainder:
        raise ValueError("decoded doubled output differs modulo 2^168")
    return Relation(inputs, outputs, target, doubled, wrap, oh - majority)


def observe(source: bytes) -> Relation:
    """Run only synthetic source material through the generated kernel."""
    if len(source) != 216:
        raise ValueError("expected 216 source bytes")
    destination = bytearray(144)
    monolith6.execute(destination, source)
    return relation(source, bytes(destination))


def high_bit_witness() -> tuple[Relation, Relation]:
    first = bytes(216)
    words = [0] * 54
    words[17] = 1 << 9
    return observe(first), observe(struct.pack("<54I", *words))


def main() -> None:
    rng = random.Random(0x6DEC)
    observations = [observe(rng.randbytes(216)) for _ in range(1000)]
    before, after = high_bit_witness()
    print(
        json.dumps(
            {
                "scope": "sampled exact decoded relation; source proof is a separate optional tool; wrap balance uses actual outputs",
                "cases": len(observations),
                "observed_wrap_balances": dict(Counter(value.wrap_balance for value in observations)),
                "corrected_shadow_mismatches": sum(value.output_shadow != value.corrected_shadow for value in observations),
                "high_bit_witness": {
                    "source_word": 17,
                    "source_bit": 9,
                    "decoded_inputs_equal": before.input_spans == after.input_spans,
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
