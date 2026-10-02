"""Analysis-only exact model using shared Boolean cores for words 3–5."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import TypeAlias, cast

BitRef: TypeAlias = tuple[int, int]
BitRecord: TypeAlias = tuple[int, list[BitRef]]

_DATA = json.loads(Path(__file__).with_name("monolith7_middle_model.json").read_text(encoding="utf-8"))
if _DATA["version"] != 2 or _DATA["output_words"] != [3, 4, 5]:
    raise ValueError("unsupported Monolith7 middle model")
_KERNELS = tuple((int(item["inputs"]), tuple(map(int, item["terms"]))) for item in _DATA["kernels"])
_FUNCTIONS = tuple((int(item["inputs"]), item["steps"], tuple(map(int, item["terms"]))) for item in _DATA["functions"])
_BITS = cast(list[BitRecord], _DATA["bits"])


def execute_words(source: Sequence[int]) -> tuple[int, int, int]:
    """Return the three recovered words from a 24-word Monolith7 source."""
    if len(source) < 24:
        raise ValueError("Monolith7 requires at least 24 source words")
    if len(_FUNCTIONS) != 68 or len(_BITS) != 96:
        raise ValueError("invalid Monolith7 middle model size")
    result = [0, 0, 0]
    for output_bit, (function_id, refs) in enumerate(_BITS):
        inputs, steps, terms = _FUNCTIONS[function_id]
        if len(refs) != inputs:
            raise ValueError("Monolith7 middle function arity mismatch")
        assignment = sum(((source[word] >> bit) & 1) << position for position, (word, bit) in enumerate(refs))
        for step_index, (kernel_id, arguments, inversions) in enumerate(steps):
            arity, kernel_terms = _KERNELS[kernel_id]
            if len(arguments) != arity:
                raise ValueError("Monolith7 middle kernel arity mismatch")
            selected = sum(((assignment >> argument) & 1) << position for position, argument in enumerate(arguments)) ^ inversions
            intermediate = sum((selected & term) == term for term in kernel_terms) & 1
            assignment |= intermediate << (inputs + step_index)
        value = sum((assignment & term) == term for term in terms) & 1
        result[output_bit // 32] |= value << (output_bit % 32)
    return result[0], result[1], result[2]
