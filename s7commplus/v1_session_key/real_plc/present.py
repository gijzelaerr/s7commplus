"""The PRESENT-80 block cipher variant behind the real-PLC seed and keys.

HarpoS7's Monolith9 is PRESENT-80 (standard S-box and P-layer, 31 rounds plus
whitening) applied to a byte-reversed little-endian block, and Monolith10 lays
out its round keys with three fixed deviations from the standard schedule
(``round_keys``). The transpiled originals are kept in
``old/family0/_generated`` in the repository and pinned against this module
by tests.
"""

from __future__ import annotations

from collections.abc import Sequence

KEY_OFFSET = 0x87CA995217BA31853DCE
FIRST_ROUND_KEY_OFFSET = 0x0000081000000000
VALUE_MASK = (1 << 160) - 1
_KEY_MASK = (1 << 80) - 1

SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)


def _p_layer_bit(bit: int) -> int:
    return 63 if bit == 63 else 16 * bit % 63


# S-box layer followed by the P-layer, one table per state byte.
_SP_TABLES = tuple(
    tuple(
        sum((((SBOX[value >> 4] << 4 | SBOX[value & 15]) >> bit) & 1) << _p_layer_bit(8 * byte + bit) for bit in range(8))
        for value in range(256)
    )
    for byte in range(8)
)


def _update(register: int, counter: int) -> int:
    """The PRESENT-80 key-register update: rotate left 61, S-box the top nibble, add the round counter."""
    register = ((register << 61) | (register >> 19)) & _KEY_MASK
    return ((SBOX[register >> 76] << 76) | (register & ((1 << 76) - 1))) ^ (counter << 15)


def round_keys(key: int) -> list[int]:
    """The 32 round keys Monolith10 lays out for an 80-bit key register.

    Unlike standard PRESENT, round key 0 is taken from ``key`` itself, the
    rest of the schedule runs on ``key ^ KEY_OFFSET``, and bit 6 is flipped
    after the second update.
    """
    keys = [(key >> 16) ^ FIRST_ROUND_KEY_OFFSET]
    register = _update(key ^ KEY_OFFSET, 1)
    for counter in range(1, 32):
        keys.append(register >> 16)
        register = _update(register, counter + 1) ^ (0x40 if counter == 1 else 0)
    return keys


def present_rounds(state: int, keys: list[int]) -> int:
    """PRESENT's 31 S-box/P-layer rounds and final key addition, in the specification's bit order."""
    for round_key in keys[:-1]:
        state ^= round_key
        state = (
            _SP_TABLES[0][state & 0xFF]
            | _SP_TABLES[1][(state >> 8) & 0xFF]
            | _SP_TABLES[2][(state >> 16) & 0xFF]
            | _SP_TABLES[3][(state >> 24) & 0xFF]
            | _SP_TABLES[4][(state >> 32) & 0xFF]
            | _SP_TABLES[5][(state >> 40) & 0xFF]
            | _SP_TABLES[6][(state >> 48) & 0xFF]
            | _SP_TABLES[7][state >> 56]
        )
    return state ^ keys[-1]


def _byte_reverse(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


def encrypt(block: int, key: int) -> int:
    """Monolith9: PRESENT rounds on the byte-reversed little-endian block, under ``round_keys(key)``."""
    return _byte_reverse(present_rounds(_byte_reverse(block), round_keys(key)))


def key_register(half: int) -> int:
    """Read an 80-bit value (little-endian bytes) as the big-endian key register."""
    return int.from_bytes(half.to_bytes(10, "little"), "big")


def key_halves(value: int) -> tuple[int, int]:
    """Key registers for Monolith10's two modes: the low and the high 80 bits of a 160-bit value."""
    return key_register(value & _KEY_MASK), key_register(value >> 80)


def encrypt_blocks(blocks: Sequence[int], keys: Sequence[int]) -> int:
    """Concatenate ``encrypt(block, key)`` results into one 160-bit value, as three Monolith9 calls do."""
    return sum(encrypt(block, key) << (64 * index) for index, (block, key) in enumerate(zip(blocks, keys))) & VALUE_MASK
