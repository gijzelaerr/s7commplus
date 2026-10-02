"""Decoders for HarpoS7's encoded 160-bit values.

HarpoS7's transforms exchange 160-bit values in encoded forms that the runtime
never builds:

- 60-byte buffers (Monolith8 and Monolith9 output) hold three words per bit.
  ``decode`` reads them through Monolith11's kernel as ``value ^ ENCODING_OFFSET``.
- The 72-byte Transform7/Monolith1 span holds 169 bits as local three-input
  gates over eighteen words. ``span_value`` reads them as
  ``2*payload + boundary`` modulo 2^160 - 47, the same decoder as
  ``tools/recover_monolith4_span_identity.py``.
"""

from __future__ import annotations

import struct

from . import monolith11_compact

MODULUS = (1 << 160) - 47
_OFFSET_WORDS = 0x1D9AEB51CF334EA5
# Monolith11's decode of every encoded 160-bit value is the value XOR this.
ENCODING_OFFSET = _OFFSET_WORDS | _OFFSET_WORDS << 64 | (_OFFSET_WORDS & 0xFFFFFFFF) << 128


def decode(encoded: bytes | bytearray | memoryview) -> int:
    """The 160-bit value held by a 60-byte encoded buffer (Monolith8/Monolith9 output)."""
    words = monolith11_compact.execute_words(struct.unpack("<15I", bytes(encoded[:60])) + (0,) * 15)
    return sum(word << (32 * index) for index, word in enumerate(words)) ^ ENCODING_OFFSET


def _lanes(*chunks: int) -> int:
    return sum(chunk << (32 * index) for index, chunk in enumerate(chunks))


# Span decoder masks, one 32-bit chunk per span word triple. Bit 0 is the
# boundary bit; bit i > 0 is payload bit i - 1. Each bit XORs its three inputs
# with _INVERT, applies majority or a choose(if_set, if_clear, selector) gate,
# then XORs _COMPLEMENT.
_INVERT = (
    _lanes(0x12808400, 0x10001E81, 0x88E40900, 0x8402CA04, 0xD0801200, 0x000000A0),
    _lanes(0x80002008, 0x84A20104, 0x00029002, 0x40050001, 0x000000C4, 0x00000002),
    _lanes(0x204040E2, 0x001CC02A, 0x501802D0, 0x00000050, 0x0409A912, 0x00000044),
)
_COMPLEMENT = _lanes(0x7132053E, 0xE45F9611, 0x67E35E21, 0xE216DB50, 0x951F183E, 0x00000017)
_MAJORITY = _lanes(0xD8C44282, 0x80B71907, 0x33188111, 0xE80580CB, 0x9C0A189B, 0x00000062)
# (if_set, if_clear, selector) word within the triple -> bits using that choose gate.
_CHOOSE = (
    ((0, 1, 2), _lanes(0x02208001, 0x00000000, 0x00A50800, 0x04125000, 0x41600600, 0x00000010)),
    ((0, 2, 1), _lanes(0x00010500, 0x18000680, 0x88404020, 0x00602E04, 0x00900000, 0x00000081)),
    ((1, 0, 2), _lanes(0x00003008, 0x24400000, 0x04021002, 0x01000000, 0x00004044, 0x00000100)),
    ((1, 2, 0), _lanes(0x04020000, 0x42002040, 0x00000004, 0x00800000, 0x20000000, 0x00000008)),
    ((2, 0, 1), _lanes(0x21100050, 0x0000C038, 0x00002408, 0x10000100, 0x00010020, 0x00000004)),
    ((2, 1, 0), _lanes(0x00080824, 0x01080000, 0x400002C0, 0x02080030, 0x0204A100, 0x00000000)),
)


def span_value(span: bytes | bytearray | memoryview) -> int:
    """Decode the 72-byte Transform7/Monolith1 span to the value Monolith8 re-encodes."""
    if len(span) < 72:
        raise ValueError(f"span too small ({len(span)}, need 72)")
    words = struct.unpack("<18I", bytes(span[:72]))
    inputs = [_lanes(*words[member::3]) ^ _INVERT[member] for member in range(3)]
    a, b, c = inputs
    bits = ((a & b) | (a & c) | (b & c)) & _MAJORITY
    for (if_set, if_clear, selector), selected in _CHOOSE:
        choice = inputs[if_clear] ^ ((inputs[if_set] ^ inputs[if_clear]) & inputs[selector])
        bits |= choice & selected
    return (bits ^ _COMPLEMENT) % MODULUS
