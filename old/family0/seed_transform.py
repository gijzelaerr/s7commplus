"""SeedTransform through the original Transform7/Monolith1/Monolith2 chain.

The runtime ``s7commplus...family0.seed.write_seed`` computes the same ECDH
with the ladder in ``curve.py``; see its docstring for when they differ.
``execute`` takes PreSeedTransform's encoded output, as HarpoS7 does.
"""

from __future__ import annotations

import os
import struct

from s7commplus.v1_session_key.real_plc import seed

from . import encoding, transform7_compact
from ._generated import monolith1, monolith2
from ._generated.data import TRANSFORM7_DATA

DESTINATION_SIZE = seed.SEED_LENGTH
TRANSFORM1_SIZE = 0x3C


def _check_sizes(destination: bytearray | memoryview, public_key: bytes) -> None:
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination too small ({len(destination)}, need {DESTINATION_SIZE})")
    if len(public_key) < seed.PUBLIC_KEY_LENGTH:
        raise ValueError(f"publicKey too small ({len(public_key)}, need {seed.PUBLIC_KEY_LENGTH})")


def execute(destination: bytearray | memoryview, public_key: bytes, transform1: bytes) -> None:
    """SeedTransform over PreSeedTransform's encoded 60-byte output, through the runtime ladder."""
    _check_sizes(destination, public_key)
    if len(transform1) < TRANSFORM1_SIZE:
        raise ValueError(f"transform1 too small ({len(transform1)}, need {TRANSFORM1_SIZE})")
    seed.write_seed(destination, public_key, encoding.decode(transform1))


def _monolith1_loop(buf: bytearray) -> None:
    """Monolith1.Loop: execute until result is non-zero."""
    src = bytearray(buf[:0x48])
    result = monolith1.execute(buf, bytes(src))
    while result == 0:
        src[:0x48] = buf[:0x48]
        result = monolith1.execute(buf, bytes(src))


def reference_execute_value(destination: bytearray | memoryview, public_key: bytes, pre_seed: int) -> None:
    """``seed.write_seed`` through the original Transform7/Monolith1/Monolith2 chain."""
    _check_sizes(destination, public_key)

    prng1 = bytearray(os.urandom(0x14))
    prng2 = bytearray(0x14)
    t7_dst = bytearray(transform7_compact.DESTINATION_SIZE)
    work = bytearray(5 * 4)

    t7_loop = 0
    while t7_loop == 0:
        prng2 = bytearray(os.urandom(0x14))
        transform7_compact.execute(t7_dst, prng1, prng2, TRANSFORM7_DATA[0xD8:])

        _monolith1_loop(t7_dst)
        monolith2.execute(work, bytes(t7_dst))

        t7_loop = 0
        for d in struct.unpack("<5I", work):
            t7_loop |= d

    destination[0x14:0x28] = work[:0x14]
    destination[0x28:0x3C] = prng1[:0x14]

    transform7_compact.execute(t7_dst, prng1, prng2, public_key)
    _monolith1_loop(t7_dst)

    # Monolith8 -> Transform13 -> Monolith11: Monolith11 decodes both encoded
    # inputs (their encoding offsets cancel) and XORs the values.
    masked = pre_seed ^ seed.seed_mask(encoding.span_value(t7_dst))
    destination[:0x14] = masked.to_bytes(0x14, "little")
