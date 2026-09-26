"""Analysis-only exact model covering all 36 Monolith7 output words."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

_DATA = json.loads(Path(__file__).with_name("monolith7_full_model.json").read_text(encoding="utf-8"))
if _DATA["version"] != 1 or _DATA["output_words"] != list(range(36)) or len(_DATA["bits"]) != 1152:
    raise ValueError("unsupported Monolith7 full model")
_NODES = _DATA["nodes"]
_FUNCTIONS = tuple((function["inputs"], function["root"]) for function in _DATA["functions"])
_BITS = _DATA["bits"]


def execute_words(source: Sequence[int]) -> tuple[int, ...]:
    """Evaluate every recovered bit from at least 24 source words."""
    if len(source) < 24:
        raise ValueError("Monolith7 requires at least 24 source words")
    result = [0] * 36
    for output_bit, (function_id, selectors) in enumerate(_BITS):
        inputs, node = _FUNCTIONS[function_id]
        if len(selectors) != inputs:
            raise ValueError("Monolith7 full function arity mismatch")
        while node >= 2:
            variable, low, high = _NODES[node - 2]
            word, bit = selectors[variable]
            node = high if (source[word] >> bit) & 1 else low
        result[output_bit // 32] |= node << (output_bit % 32)
    return tuple(result)
