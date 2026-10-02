"""Monolith11 — compact, human-maintained implementation.

Family-0 Monolith11 maps 30 source words to 5 destination words through
bitwise-only per-bit Boolean functions (AND/OR/XOR/NOT; no shifts, carries,
or cross-word state). Exhaustive truth-table analysis over every possible
input proved each output bit has an exact degree-2 algebraic normal form
depending on only six source bits. See ``MONOLITH11_ANALYSIS.md`` for the
derivation and ``tests/test_v1_session_key_bitwise_analysis.py`` for the
equivalence proof: all 5x32 output bits, the upstream known-answer vector,
and 100 random vectors cross-checked against the retained generated code.

``encoding.decode`` uses it to read encoded 160-bit values. The runtime no
longer needs either, because it passes decoded integers between transforms.
``_generated/monolith11.py`` (HarpoS7-derived, MIT-licensed; see
``LICENSE-HarpoS7``) is the transpiled original it replaces.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

# 32-bit ANF coefficient masks, not secret material. For each source triple
# (a, b, c) the kernel computes six terms: a, b, a&b, c, a&c, b&c.
EVEN_COEFFICIENTS = (0x5DA724BA, 0x6250A363, 0xF6BDFCF6, 0x86F79499, 0xAFFF4FDF, 0x5FFBFBAF)
ODD_COEFFICIENTS = (0xECB2D69E, 0xC6D87455, 0xDFDFDF77, 0x104A21AB, 0xA7773DFB, 0x7DEFFE9F)

_U32 = 0xFFFFFFFF


def _kernel(a: int, b: int, c: int, coefficients: tuple[int, ...]) -> int:
    return (
        (a & coefficients[0])
        ^ (b & coefficients[1])
        ^ (a & b & coefficients[2])
        ^ (c & coefficients[3])
        ^ (a & c & coefficients[4])
        ^ (b & c & coefficients[5])
    )


def execute_words(source: Sequence[int]) -> tuple[int, ...]:
    """Map 30 source words to five destination words.

    Output word ``i`` XORs the same kernel over source triples starting at
    ``3*i`` and ``15 + 3*i``. Even and odd output words use different masks.
    """
    if len(source) < 30:
        raise ValueError("Monolith11 requires at least 30 source words")
    output = []
    for index in range(5):
        coefficients = EVEN_COEFFICIENTS if index % 2 == 0 else ODD_COEFFICIENTS
        left_start = 3 * index
        right_start = 15 + left_start
        left = _kernel(source[left_start], source[left_start + 1], source[left_start + 2], coefficients)
        right = _kernel(source[right_start], source[right_start + 1], source[right_start + 2], coefficients)
        output.append((left ^ right) & _U32)
    return tuple(output)


def execute(destination: bytearray, source: bytes) -> None:
    """Write the five Monolith11 output words into ``destination[:20]``.

    Signature matches the transpiled ``_generated/monolith11.py`` entry
    point: ``source`` supplies (at least) 30 little-endian uint32 words, and
    only the first 20 bytes of ``destination`` are written — the generated
    version also left ``destination[20:]`` unchanged, so this is a no-op
    difference, not a behavior change.
    """
    words = struct.unpack("<30I", bytes(source[:120]))
    destination[:20] = struct.pack("<5I", *execute_words(words))
