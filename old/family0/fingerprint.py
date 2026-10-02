"""HarpoS7's challenge fingerprint and the white-boxed gate network it computes.

``harpo_fingerprint`` is the direct port of ``HarpoS7.Fingerprint.HarpoFingerprint``
and ``ContextMutator``. HarpoS7 computes each gate's output from a
``fp_data2.bin`` nibble XOR a nibble of a 47-word context that ContextMutator
changes between the 20 rounds. That context never depends on the challenge,
so ``gates`` evaluates the same formulas once for all 256 inputs of every gate,
and ``evaluate`` runs the resulting fixed network. ``tools/recover_fingerprint.py``
recovers the cipher in ``s7commplus/v1_session_key/real_plc/fingerprint.py`` from
that network.
"""

from __future__ import annotations

import struct

from ._generated.data import FP_DATA1, FP_DATA2
from ._generated.data._constants import FP_BIG_CONTEXT_INIT_INTS, FP_MUTATIONS, FP_XOR_MAGIC_INTS

FINGERPRINT_LENGTH = 8
_SMALL_CTX_LEN = 272
_NUM_MUTATIONS = 20
_STEP_BYTES = 0x80  # FP_DATA2 bytes each gate reads its table from
_U32 = 0xFFFFFFFF

_OP = {"+": int.__add__, "*": int.__mul__, "^": int.__xor__}

Gate = tuple[int, int, int, bytes]


def _load_collection(data: bytes) -> list[bytes]:
    lengths = struct.unpack("<20I", data[:80])
    offset = 80
    result = []
    for length in lengths:
        result.append(data[offset : offset + length * 2])
        offset += length * 2
    return result


_DATA1 = [list(struct.unpack(f"<{len(chunk) // 2}H", chunk)) for chunk in _load_collection(FP_DATA1)]
_DATA2 = [list(struct.unpack(f"<{len(chunk) // 2}H", chunk)) for chunk in _load_collection(FP_DATA2)]


# --- The direct port of HarpoFingerprint/ContextMutator, kept verbatim. ---


def harpo_fingerprint(destination: bytearray, challenge: bytes) -> None:
    if len(destination) < FINGERPRINT_LENGTH:
        raise ValueError("destination must be at least 8 bytes")
    if len(challenge) < 18:
        raise ValueError("challenge must be at least 18 bytes")

    small_ctx = bytearray(_SMALL_CTX_LEN)
    big_ctx = list(FP_BIG_CONTEXT_INIT_INTS)

    small_ctx[:16] = challenge[2:18]

    for i in range(_NUM_MUTATIONS):
        _sub_procedure(_DATA1[i], FP_XOR_MAGIC_INTS[i], _DATA2[i], small_ctx, big_ctx)
        _mutate(big_ctx, i)

    _final_fingerprint(destination, small_ctx)


def _pwvar_mask(value: int) -> int:
    return (((value & 1) * -4) + 4) & 0x1F


def _pwvar_read(value: int, small_ctx: bytearray) -> int:
    return (small_ctx[value >> 1] >> _pwvar_mask(value & 0xFF)) & 0xFF


def _sub_procedure(
    data1: list[int],
    xor_magic: int,
    data2: list[int],
    small_ctx: bytearray,
    big_ctx: list[int],
) -> None:
    data2_bytes = struct.pack(f"<{len(data2)}H", *data2)

    index = 0
    ctx_offset = 0

    while index < len(data1):
        pw_var0 = _pwvar_read(data1[index], small_ctx)
        index += 1
        pw_var1 = _pwvar_read(data1[index], small_ctx)
        index += 1
        pw_var2 = data1[index]
        index += 1

        static3 = ((pw_var1 & 0xF) | (pw_var0 << 4)) & 0xFF

        t1 = (static3 >> 3) + (ctx_offset >> 2)
        mod = int(t1) % 0x2F
        t3 = big_ctx[mod]
        static6 = (t3 ^ xor_magic) & _U32

        t4 = ((0x7 - (pw_var1 & 0x7)) * 0x04) & 0x1F
        static5 = (static6 >> t4) & 0xFF

        b_var3 = (((pw_var2 & 0xFF) & 1) * (-4) + 4) & 0xFF
        ctx_buffer_index = pw_var2 >> 1

        t5 = b_var3 & 0x1F
        data2_index = ((static3 >> 1) + ctx_offset) & 0xFFFFFFFF

        if data2_index < len(data2_bytes):
            data2_byte = data2_bytes[data2_index]
        else:
            data2_byte = 0

        f_val = (
            (((data2_byte >> _pwvar_mask(pw_var1 & 0xFF)) ^ static5) & 0xF) << t5 | ((0xF0 >> t5) & small_ctx[ctx_buffer_index])
        ) & 0xFF

        small_ctx[ctx_buffer_index] = f_val

        ctx_offset += 0x80


def _mutate(big_ctx: list[int], mutation_index: int) -> None:
    for idx, op, val in FP_MUTATIONS[mutation_index]:
        big_ctx[idx] = _OP[op](big_ctx[idx], val) & _U32


def _final_fingerprint(fp: bytearray, sc: bytearray) -> None:
    fp[0] = ((sc[93] << 4) | (sc[224] >> 4)) & 0xFF
    fp[1] = ((((fp[1] ^ sc[189]) & 0xF ^ sc[189]) ^ sc[53]) & 0xF ^ ((fp[1] ^ sc[189]) & 0xF ^ sc[189])) & 0xFF
    fp[2] = (((fp[2] & 0xF | sc[119] << 4) ^ sc[86]) & 0xF ^ (fp[2] & 0xF | sc[119] << 4)) & 0xFF
    fp[3] = (((fp[3] ^ sc[83]) & 0xF ^ sc[83]) & 0xF0 | (sc[33] >> 4)) & 0xFF
    fp[4] = ((((fp[4] ^ sc[229]) & 0xF ^ sc[229]) ^ sc[58]) & 0xF ^ ((fp[4] ^ sc[229]) & 0xF ^ sc[229])) & 0xFF
    fp[5] = ((((fp[5] ^ sc[69]) & 0xF ^ sc[69]) ^ sc[165]) & 0xF ^ ((fp[5] ^ sc[69]) & 0xF ^ sc[69])) & 0xFF
    fp[6] = (((fp[6] ^ sc[63]) & 0xF ^ sc[63]) & 0xF0 | (sc[89] >> 4)) & 0xFF
    fp[7] = ((((fp[7] ^ sc[172]) & 0xF ^ sc[172]) ^ sc[247]) & 0xF ^ ((fp[7] ^ sc[172]) & 0xF ^ sc[172])) & 0xFF


# --- The same computation as a fixed gate network. ---


def _gate_table(data: bytes, context: list[int], xor_magic: int, step: int) -> bytes:
    """The 256-entry table of one gate, indexed by ``a << 4 | b``."""
    block = data[step * _STEP_BYTES : (step + 1) * _STEP_BYTES]
    table = bytearray(256)
    for ab in range(256):
        b = ab & 0xF
        data_byte = block[ab >> 1]
        data_nibble = data_byte >> 4 if b & 1 == 0 else data_byte & 0xF
        word = context[((ab >> 3) + step * (_STEP_BYTES >> 2)) % len(context)] ^ xor_magic
        table[ab] = data_nibble ^ ((word >> (4 * (7 - (b & 7)))) & 0xF)
    return bytes(table)


def gates() -> list[Gate]:
    """Every gate as ``(a, b, dst, table)`` in execution order, from HarpoS7's tables."""
    context = list(FP_BIG_CONTEXT_INIT_INTS)
    result = []
    for round_index, (wiring, data) in enumerate(zip(_load_collection(FP_DATA1), _load_collection(FP_DATA2))):
        wires = struct.unpack(f"<{len(wiring) // 2}H", wiring)
        for step in range(len(wires) // 3):
            a, b, dst = wires[3 * step : 3 * step + 3]
            result.append((a, b, dst, _gate_table(data, context, FP_XOR_MAGIC_INTS[round_index], step)))
        for index, op, value in FP_MUTATIONS[round_index]:
            context[index] = _OP[op](context[index], value) & _U32
    return result


def evaluate(network: list[Gate], challenge: bytes) -> bytes:
    """The fingerprint of ``challenge`` computed by the gate network."""
    state = [0] * 544
    for index, byte in enumerate(challenge[2:18]):
        state[2 * index], state[2 * index + 1] = byte >> 4, byte & 0xF
    for a, b, dst, table in network:
        state[dst] = table[state[a] << 4 | state[b]]
    return bytes(state[_OUTPUT[2 * i]] << 4 | state[_OUTPUT[2 * i + 1]] for i in range(FINGERPRINT_LENGTH))


# Final-state nibbles that form the fingerprint, most significant first.
_OUTPUT = (187, 448, 378, 107, 239, 173, 166, 66, 458, 117, 138, 331, 126, 178, 344, 495)
