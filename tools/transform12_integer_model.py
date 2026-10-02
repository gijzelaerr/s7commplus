"""Integer semantics for canonical Transform12 packed operands.

These are compatibility equations, not a replacement field implementation.
The four primitives are the runtime ``family0/transform12_compact`` ones,
re-exported so analysis and runtime cannot drift; no Prepare/Finalize or
packed BigInt helper is used here.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from old.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from old.family0.transform12_compact import add, multiply, subtract

if TYPE_CHECKING:
    from tools.decompile_transform12 import Operand, Program

BITS = 160
LIMIT = 1 << BITS
MASK = LIMIT - 1
FOLD = 47
CANDIDATE_MODULUS = LIMIT - FOLD
WORD_MASK = (1 << 32) - 1


def encode(value: int) -> bytes:
    """Encode a 160-bit representative as five 28-bit lanes and one 20-bit lane."""
    if not 0 <= value < LIMIT:
        raise ValueError("representative must be an unsigned 160-bit integer")
    return struct.pack("<6I", *((value >> (28 * lane) & ((1 << 28) - 1)) << 2 for lane in range(6)))


def decode(packed: bytes) -> int:
    """Decode only canonical lane packing; arbitrary Prepare inputs are excluded."""
    if len(packed) != 24:
        raise ValueError("packed operand must contain exactly 24 bytes")
    words = struct.unpack("<6I", packed)
    if any(word & ~0x3FFFFFFC for word in words[:5]) or words[5] & ~0x3FFFFC:
        raise ValueError("operand is not canonical lane packing")
    return sum((word >> 2) << (28 * lane) for lane, word in enumerate(words))


def square(a: int) -> int:
    """Square using the same compression semantics as multiplication."""
    return multiply(a, a)


def execute_program(program: Program, context: bytearray, constants: bytes = TRANSFORM12_BIG_INT_DATA) -> None:
    """Evaluate decoded SSA without invoking any runtime arithmetic primitive.

    Entry context and constants must use canonical lane packing. Outputs retain
    the exact representative rather than reducing modulo CANDIDATE_MODULUS.
    """
    if len(context) < program.context_slots * 24 or len(constants) < program.constant_slots * 24:
        raise ValueError("context or constant table is shorter than the declared program buffer")
    values: dict[int, int] = {}

    def resolve(operand: Operand) -> int:
        if operand.kind == "value":
            return values[operand.index]
        buffer = constants if operand.kind == "constant" else context
        offset = operand.index * 24
        return decode(bytes(buffer[offset : offset + 24]))

    for instruction in program.instructions:
        operands = [resolve(operand) for operand in instruction.operands]
        if instruction.operation == "square":
            result = square(operands[0])
        else:
            operation = {"multiply": multiply, "add": add, "subtract": subtract}[instruction.operation]
            result = operation(*operands)
        values[instruction.value] = result
    outputs = [(slot, encode(resolve(operand))) for slot, operand in program.outputs]
    for slot, packed in outputs:
        context[slot * 24 : (slot + 1) * 24] = packed
