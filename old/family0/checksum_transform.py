"""HarpoS7's table-driven ChecksumTransform.

Manual port of ``HarpoS7.Family0.Transforms.ChecksumTransform``. With
``lookup_table`` from ``lut_generator.execute(table, h)``, ``execute`` computes
``key * h`` in the field of ``s7commplus.v1_session_key.real_plc.checksum``, which
the runtime multiplies directly. The work buffer is a uint32[8] 256-bit product
that the port walks one key byte at a time and reduces in its final mixing step.
"""

from __future__ import annotations

import struct

KEY_SIZE = 0x10
DESTINATION_SIZE = 0x10
LOOKUP_TABLE_SIZE = 0x1000

_U32 = 0xFFFFFFFF


def _xor_128(work: list[int], offset: int, lut: list[int], lut_index: int) -> None:
    """XOR four uint32s from ``lut[lut_index..lut_index+4]`` into
    ``work[offset..offset+4]`` in place."""
    for i in range(4):
        work[offset + i] ^= lut[lut_index + i]


def execute(destination: bytearray, key: bytes, lookup_table: bytes) -> None:
    """Compute the 16-byte checksum.

    Args:
        destination: 16-byte buffer for the result.
        key: 16-byte input key.
        lookup_table: 4 KB table from ``lut_generator.execute``.
    """
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination must be at least {DESTINATION_SIZE} bytes")
    if len(key) < KEY_SIZE:
        raise ValueError(f"key must be at least {KEY_SIZE} bytes")
    if len(lookup_table) < LOOKUP_TABLE_SIZE:
        raise ValueError(f"lookup_table must be at least {LOOKUP_TABLE_SIZE} bytes")

    work = [0] * 8

    key_dwords = list(struct.unpack("<4I", bytes(key[:16])))
    lut_dwords = list(struct.unpack(f"<{LOOKUP_TABLE_SIZE // 4}I", bytes(lookup_table[:LOOKUP_TABLE_SIZE])))

    # Walk key bytes from byte 3 down to byte 1 (in each uint32 of the key).
    for i in (0x18, 0x10, 0x08):
        for j in range(4):
            lut_index = ((key_dwords[j] >> i) & 0xFF) << 2
            _xor_128(work, j, lut_dwords, lut_index)

        # Rotate work buffer left by one byte.
        for j in range(7, 0, -1):
            work[j] = ((work[j - 1] >> 0x18) | ((work[j] << 0x08) & _U32)) & _U32
        work[0] = (work[0] << 0x08) & _U32

    # Final round: lowest byte of each key uint32.
    for i in range(4):
        lut_index = (key_dwords[i] & 0xFF) << 2
        _xor_128(work, i, lut_dwords, lut_index)

    # Final mixing.
    temp = (((work[7] >> 0x0D) ^ work[7]) >> 0x11 ^ work[4] ^ work[7]) & _U32

    dst = [0] * 4
    dst[0] = (((((temp << 0x0D) & _U32) ^ temp) << 0x02) & _U32 ^ work[0] ^ temp) & _U32
    dst[1] = (
        ((temp >> 0x0D) ^ temp) >> 0x11 ^ ((((work[5] << 0x0D) & _U32) ^ work[5]) << 2) & _U32 ^ work[1] ^ temp ^ work[5]
    ) & _U32
    dst[2] = (
        ((work[5] >> 0x0D) ^ work[5]) >> 0x11 ^ ((((work[6] << 0x0D) & _U32) ^ work[6]) << 2) & _U32 ^ work[2] ^ work[5] ^ work[6]
    ) & _U32
    dst[3] = (
        ((work[6] >> 0x0D) ^ work[6]) >> 0x11 ^ ((((work[7] << 0x0D) & _U32) ^ work[7]) << 2) & _U32 ^ work[3] ^ work[6] ^ work[7]
    ) & _U32

    struct.pack_into("<4I", destination, 0, *dst)
