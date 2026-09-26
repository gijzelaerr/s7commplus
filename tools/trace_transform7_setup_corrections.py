"""Compose every source-derived setup correction, then trace synthetic inputs.

Wrap balances use actual encoded outputs; this is NOT an input-only replacement
or a proof that wraps vanish on all legal setups. Single-threaded patching only;
never supply live authentication material. No runtime code is changed.
"""

from __future__ import annotations

import json
import random
import struct
from collections import Counter
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from unittest.mock import patch

from s7commplus.session_auth.family0 import transform7
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools import transform12_integer_model as arithmetic
from tools.recover_monolith3_span_identity import relation as plain_relation
from tools.recover_monolith4_span_identity import candidate_add, normalized_span
from tools.recover_monolith5_span_decoder import MODULUS, P
from tools.recover_monolith6_span_identity import H, relation as pair_relation
from tools.recover_transform7_setup import SLOTS, capture_setup, targeted_base_point_probe
from tools.trace_transform7_setup_shadows import NAMES, compose, span_shadow
from tools.transform7_setup_merge import SETUP_ADD_SLOTS, decode_payload, merge


@dataclass(frozen=True)
class WrapperCorrection:
    index: int
    operation: str
    wrap_balance: int
    plain_truncation: int
    correction: int
    expected_without_correction: int
    actual: int


def wrapper_correction(index: int, name: str, inputs: tuple[bytes, ...], outputs: tuple[bytes, ...]) -> WrapperCorrection:
    """Measure wrap/truncation separately from the field-residue discrepancy.

    Inputs and outputs must be pre/post-call copies, not aliased live buffers.
    Monolith4's overflow is input-derived. The other wrap balances still depend
    on output payloads, so this cannot generate an encoded replacement.
    """
    expected_outputs = 1 if name == NAMES[1] else 2
    expected_inputs = 2 if name == NAMES[1] else 3
    if name not in NAMES or len(inputs) != expected_inputs or len(outputs) != expected_outputs:
        raise ValueError("unexpected setup wrapper signature")
    if any(len(value) != (24 if name == NAMES[0] and i == 2 else 72) for i, value in enumerate(inputs)):
        raise ValueError("unexpected setup wrapper input length")
    if any(len(value) != (24 if name == NAMES[2] else 72) for value in outputs):
        raise ValueError("unexpected setup wrapper output length")
    values = [span_shadow(value) for value in inputs[:2]]
    truncation = 0
    if name == NAMES[0]:
        decoded = plain_relation(b"".join(inputs), b"".join(outputs))
        wrap = decoded.wrap_balance
        truncation = decoded.plain_original >> 170
        correction = (MODULUS // 2 % P) * wrap - (MODULUS % P) * truncation
        expected = (H * sum(values) + H * H * decoded.plain_original) % P
    elif name == NAMES[1]:
        payload, boundary, overflow = candidate_add(*inputs)
        if normalized_span(struct.unpack("<18I", outputs[0])) != (payload, boundary):
            raise AssertionError("Monolith4 decoded addition disagrees with generated output")
        wrap = -int(overflow)
        correction = (MODULUS % P) * wrap
        expected = sum(values) % P
    elif name == NAMES[2]:
        spans = [normalized_span(struct.unpack("<18I", value)) for value in inputs]
        hs = sum(h for _, h in spans)
        target = sum(b for b, _ in spans) + H * (hs % 2) + int(hs >= 2)
        total = sum(decode_payload(value) for value in outputs)
        wrap, remainder = divmod(total - target, MODULUS)
        if remainder:
            raise AssertionError("Monolith5 combined payload disagrees modulo 2^168")
        correction = (MODULUS % P) * wrap
        expected = (sum(values) + span_shadow(inputs[2])) % P
    else:
        pair = pair_relation(b"".join(inputs), b"".join(outputs))
        wrap = pair.wrap_balance
        correction = (MODULUS // 2 % P) * wrap
        expected = H * (sum(values) + span_shadow(inputs[2])) % P
    actual = sum(decode_payload(value) if name == NAMES[2] else span_shadow(value) for value in outputs) % P
    if actual != (expected + correction) % P:
        raise AssertionError("source-derived wrapper correction disagrees with observed shadow")
    return WrapperCorrection(index, name, wrap, truncation, correction, expected, actual)


@dataclass(frozen=True)
class SetupTrace:
    wrappers: tuple[WrapperCorrection, ...]
    merge_corrections: tuple[tuple[int, int], ...]
    predicted: tuple[int, ...]
    actual: tuple[int, ...]


def trace(x: int, y: int, r: int) -> SetupTrace:
    """Evaluate corrected source composition against all four real context slots."""
    observations: list[WrapperCorrection] = []
    merges: list[tuple[int, int]] = []

    def wrap(name: str, original: Callable[..., None]) -> Callable[..., None]:
        def execute(*buffers: memoryview | bytes) -> None:
            count = 1 if name == NAMES[1] else 2
            inputs = tuple(bytes(buffer[: 24 if name == NAMES[0] and i == 2 else 72]) for i, buffer in enumerate(buffers[count:]))
            original(*buffers)
            outputs = tuple(bytes(buffer[: 24 if name == NAMES[2] else 72]) for buffer in buffers[:count])
            observations.append(wrapper_correction(len(observations), name, inputs, outputs))

        return execute

    original_merge = transform7.big_int_addition

    def observe_merge(destination: bytearray | memoryview, first: bytes, second: bytes) -> None:
        if len(merges) >= len(SETUP_ADD_SLOTS):
            raise ValueError("unexpected additional setup merge")
        modeled = merge(decode_payload(bytes(first[:24])), decode_payload(bytes(second[:24])))
        original_merge(destination, first, second)
        if bytes(destination[:24]) != arithmetic.encode(modeled.result):
            raise AssertionError("derived merge disagrees with generated bytes")
        merges.append((SETUP_ADD_SLOTS[len(merges)], modeled.residue_correction))

    with ExitStack() as stack:
        for name in NAMES:
            stack.enter_context(patch.object(transform7, name, wrap(name, getattr(transform7, name))))
        stack.enter_context(patch.object(transform7, "big_int_addition", observe_merge))
        actual = tuple(value % P for value in capture_setup(x, y, r))
    if len(observations) != 23 or len(merges) != 4:
        raise ValueError("expected all setup wrappers and merges")
    values = {"X": x, "Y": y | 4, "R": r | 4, "d": span_shadow(TRANSFORM7_DATA[72:144])}
    if span_shadow(TRANSFORM7_DATA[:72]) != 0:
        raise ValueError("bundled zero span changed")
    values.update((f"c{value.index}", value.correction) for value in observations)
    values.update((f"merge{slot}", correction) for slot, correction in merges)
    expressions = compose(corrected=True)
    predicted = tuple(expressions[slot].evaluate(values) for slot in SLOTS)
    return SetupTrace(tuple(observations), tuple(merges), predicted, actual)


def main() -> None:
    rng = random.Random(0xC7346)
    cases = [(0, 0, 0), (1, 1, 1), ((1 << 160) - 1,) * 3, targeted_base_point_probe()]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(128))
    traces = [trace(*case) for case in cases]
    print(
        json.dumps(
            {
                "scope": "source-derived correction composition; synthetic traces, NOT input-only equivalence or universal zero-wrap proof",
                "cases": len(cases),
                "wrapper_observations": sum(len(value.wrappers) for value in traces),
                "wrap_balances": {
                    name: dict(Counter(w.wrap_balance for value in traces for w in value.wrappers if w.operation == name))
                    for name in NAMES
                },
                "plain_truncations": dict(
                    Counter(w.plain_truncation for value in traces for w in value.wrappers if w.operation == NAMES[0])
                ),
                "merge_corrections": dict(Counter(c for value in traces for _, c in value.merge_corrections)),
                "mismatch_case_indexes": [i for i, value in enumerate(traces) if value.predicted != value.actual],
                "composition": {
                    slot: {name: str(value) for name, value in expression.terms}
                    for slot, expression in compose(corrected=True).items()
                },
                "targeted_probe": asdict(traces[3]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
