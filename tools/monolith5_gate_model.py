"""Analysis-only Monolith5 model evaluating named gates across 32 bit lanes."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from tools.monolith5_model import Component, Entry
    from tools.recover_monolith5_gates import Gate

_DATA = json.loads(Path(__file__).with_name("monolith5_gate_model.json").read_text(encoding="utf-8"))
if _DATA["version"] != 1 or len(_DATA["functions"]) != 32:
    raise ValueError("unsupported Monolith5 gate model")
_FUNCTIONS = cast("list[Gate]", _DATA["functions"])
_POSITIONS = json.loads(Path(__file__).with_name("monolith5_model.json").read_text(encoding="utf-8"))
_ENTRIES = cast("list[Entry]", _POSITIONS["entries"])
_U32 = 0xFFFFFFFF


def evaluate_lane(function_id: int, source: Sequence[int]) -> int:
    """Evaluate one nine-input function in parallel on uint32 input lanes."""
    if len(source) != 9:
        raise ValueError("lane function requires nine input words")
    if not 0 <= function_id < 32:
        raise ValueError("Monolith5 function ID must be 0..31")
    function = _FUNCTIONS[function_id]
    spans = []
    for span in range(3):
        a, b, c = (
            source[span * 3 + source_index] ^ (_U32 if function["inversions"] & (1 << position) else 0)
            for position, source_index in enumerate(function["order"])
        )
        spans.append(b ^ ((a ^ b) & c) if function["gate"] == "choose" else (a & b) ^ (a & c) ^ (b & c))
    a, b, c = spans
    combine = function["combine"]
    if combine == "xor3":
        return (a ^ b ^ c) & _U32
    if combine == "majority":
        return ((a & b) ^ (a & c) ^ (b & c)) & _U32
    if combine == "or3":
        return (a | b | c) & _U32
    if combine == "not_all_equal":
        return ((a | b | c) ^ (a & b & c)) & _U32
    raise ValueError("unknown Monolith5 combine")


def execute_words(source: Sequence[int]) -> tuple[int, ...]:
    """Map 54 source words to twelve destination words using shared span gates."""
    if len(source) < 54:
        raise ValueError("Monolith5 requires at least 54 source words")
    if len(_ENTRIES) != 168:
        raise ValueError("invalid Monolith5 position model size")
    cache: dict[tuple[int, int], int] = {}

    def lane(component: Component) -> int:
        chunk, bit, function_id = component
        key = chunk, function_id
        if key not in cache:
            cache[key] = evaluate_lane(
                function_id, [source[span * 18 + chunk * 3 + value] for span in range(3) for value in range(3)]
            )
        return (cache[key] >> bit) & 1

    first = 0
    second = 0
    for position, (constant, components, second_mask, residual) in enumerate(_ENTRIES):
        values = [lane(component) for component in components]
        first_bit = constant
        for value in values:
            first_bit ^= value
        first |= first_bit << position
        if position < 167:
            second_bit = lane(residual) if residual is not None else 0
            for subset in range(1 << len(values)):
                if second_mask & (1 << subset) and all(values[index] for index in range(len(values)) if subset & (1 << index)):
                    second_bit ^= 1
            second |= second_bit << (position + 1)
    return tuple(((stream >> (28 * word)) & 0x0FFFFFFF) << 2 for stream in (first, second) for word in range(6))
