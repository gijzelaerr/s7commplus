"""PreSeedTransform's encoded reference: Monolith9 over the Transform1 work buffer.

Manual port of ``HarpoS7.Family0.Transforms.PreSeedTransform``. The runtime
computes the decoded value with ``s7commplus...family0.seed.pre_seed``.
"""

from __future__ import annotations

import struct

from ._generated import monolith9
from ._generated.data import TRANSFORM1_DATA

SOURCE_SIZE = 0x18
DESTINATION_SIZE = 0x3C
_MAGIC_POSTFIX = struct.pack("<III", 0x4F5BB379, 0x90BA725F, 0x36A4D7BB)


def execute(destination: bytearray, source: bytes) -> None:
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination too small ({len(destination)}, need {DESTINATION_SIZE})")
    if len(source) < SOURCE_SIZE:
        raise ValueError(f"source too small ({len(source)}, need {SOURCE_SIZE})")

    work = bytearray(0xC5 * 4)
    work[: len(TRANSFORM1_DATA)] = TRANSFORM1_DATA

    magic_offset = 0xC2 * 4
    work[magic_offset : magic_offset + 12] = _MAGIC_POSTFIX

    src_dwords = struct.unpack(f"<{SOURCE_SIZE // 4}I", source[:SOURCE_SIZE])

    for i in range(3):
        struct.pack_into("<II", work, 0xC0 * 4, src_dwords[i * 2], src_dwords[i * 2 + 1])

        m9_dst = bytearray(24)  # 6 uints
        monolith9.execute(m9_dst, bytes(work))

        copy_len = 24 if i < 2 else 12  # 6 uints or 3 uints
        destination[i * 24 : i * 24 + copy_len] = m9_dst[:copy_len]
