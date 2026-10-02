"""HarpoFingerprint — challenge fingerprinting for session key derivation.

Produces an 8-byte fingerprint from a PLC challenge. Used by
DeriveSessionKey to build the HMAC-SHA256 input that yields the
24-byte session key.

HarpoS7 computes the fingerprint with a white-boxed network of 496 nibble
lookup gates. Underneath the white-box encodings it is a fixed-key
substitution-permutation network on AES's inverse S-box. Write ``crumb(v, j)``
for bits ``j`` and ``j + 4`` of byte ``v`` as a 2-bit value; then:

1. ``y = InvSubBytes(challenge[2:18] ^ INPUT_KEY)`` (16 bytes);
2. the 8-byte state is ``y[0:8] ^ y[8:16]``;
3. each of 13 rounds replaces the state with 8 new bytes. New byte ``s`` is
   ``InvSbox(w ^ key)`` where ``w`` holds crumb ``j`` of four source bytes,
   the first source in bits 0-1. Each round splits the state into two groups
   of four bytes and transposes each group's 4x4 grid of crumbs;
4. fingerprint nibble ``n`` is ``OUTPUT_ENCODING[n]`` applied to crumb ``j``
   of bytes ``a`` and ``b`` (``a`` in bits 0-1). These 16 fixed 4-bit
   bijections are not affine and look like the white-box's external output
   encoding.

``tools/recover_fingerprint.py`` recovers every constant below from HarpoS7's
gate network (kept in ``old/family0/fingerprint.py`` in the repository) and
checks this module against it; each recovered key byte and source order is
the only one that fits. The wiring follows no evident schedule and the keys
no evident key schedule, so this is probably a generated cipher rather than a
published one.
"""

from __future__ import annotations

FINGERPRINT_LENGTH = 8

INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
)

INPUT_KEY = bytes.fromhex("84bf37e056af421191579ebc641c9fb3")

# Per round, the key byte of each of the 8 S-boxes.
ROUND_KEYS = (
    bytes.fromhex("3be4b25d87bcc3db"),
    bytes.fromhex("ad4c460f7324d5cf"),
    bytes.fromhex("643ee25f3892b80e"),
    bytes.fromhex("d352fe09ba330dea"),
    bytes.fromhex("2525c6a827cee55b"),
    bytes.fromhex("71f7c262b60c0900"),
    bytes.fromhex("54f7229eba99cbc6"),
    bytes.fromhex("40a2f2cad7bfe29d"),
    bytes.fromhex("bda945cd3d9beef6"),
    bytes.fromhex("d2a3717b0ee1b5a4"),
    bytes.fromhex("daa465fa78e749e0"),
    bytes.fromhex("7600329783ca7cfe"),
    bytes.fromhex("fe5240529c64dfd6"),
)

# Per round, for each new state byte: (crumb j, the four source bytes, low crumb first).
# fmt: off
ROUND_WIRING: tuple[tuple[tuple[int, tuple[int, int, int, int]], ...], ...] = (
    ((1, (7, 6, 5, 4)), (0, (3, 2, 1, 0)), (0, (7, 6, 5, 4)), (1, (3, 2, 1, 0)), (2, (7, 6, 5, 4)), (2, (3, 2, 1, 0)), (3, (7, 6, 5, 4)), (3, (3, 2, 1, 0))),
    ((2, (2, 1, 0, 3)), (3, (2, 1, 0, 3)), (1, (2, 1, 0, 3)), (0, (2, 1, 0, 3)), (2, (4, 5, 6, 7)), (3, (4, 5, 6, 7)), (1, (4, 5, 6, 7)), (0, (4, 5, 6, 7))),
    ((3, (0, 4, 1, 5)), (2, (0, 4, 1, 5)), (0, (0, 4, 1, 5)), (1, (0, 4, 1, 5)), (3, (3, 7, 2, 6)), (2, (3, 7, 2, 6)), (0, (3, 7, 2, 6)), (1, (3, 7, 2, 6))),
    ((2, (5, 1, 4, 0)), (1, (5, 1, 4, 0)), (0, (5, 1, 4, 0)), (3, (5, 1, 4, 0)), (2, (6, 2, 7, 3)), (3, (6, 2, 7, 3)), (1, (6, 2, 7, 3)), (0, (6, 2, 7, 3))),
    ((3, (4, 0, 5, 3)), (2, (4, 0, 5, 3)), (1, (4, 0, 5, 3)), (0, (4, 0, 5, 3)), (0, (7, 2, 6, 1)), (1, (7, 2, 6, 1)), (3, (7, 2, 6, 1)), (2, (7, 2, 6, 1))),
    ((1, (4, 3, 5, 2)), (3, (4, 3, 5, 2)), (0, (4, 3, 5, 2)), (2, (4, 3, 5, 2)), (2, (7, 1, 6, 0)), (0, (7, 1, 6, 0)), (1, (7, 1, 6, 0)), (3, (7, 1, 6, 0))),
    ((0, (3, 4, 1, 7)), (2, (2, 5, 0, 6)), (3, (2, 5, 0, 6)), (2, (3, 4, 1, 7)), (1, (3, 4, 1, 7)), (3, (3, 4, 1, 7)), (1, (2, 5, 0, 6)), (0, (2, 5, 0, 6))),
    ((3, (1, 3, 2, 5)), (2, (1, 3, 2, 5)), (0, (1, 3, 2, 5)), (2, (7, 0, 6, 4)), (1, (1, 3, 2, 5)), (0, (7, 0, 6, 4)), (1, (7, 0, 6, 4)), (3, (7, 0, 6, 4))),
    ((0, (5, 2, 6, 4)), (1, (3, 1, 7, 0)), (1, (5, 2, 6, 4)), (3, (3, 1, 7, 0)), (2, (5, 2, 6, 4)), (2, (3, 1, 7, 0)), (3, (5, 2, 6, 4)), (0, (3, 1, 7, 0))),
    ((2, (0, 7, 2, 1)), (0, (4, 5, 6, 3)), (3, (0, 7, 2, 1)), (1, (4, 5, 6, 3)), (3, (4, 5, 6, 3)), (1, (0, 7, 2, 1)), (2, (4, 5, 6, 3)), (0, (0, 7, 2, 1))),
    ((2, (0, 6, 2, 4)), (3, (0, 6, 2, 4)), (0, (0, 6, 2, 4)), (3, (7, 1, 5, 3)), (2, (7, 1, 5, 3)), (1, (7, 1, 5, 3)), (1, (0, 6, 2, 4)), (0, (7, 1, 5, 3))),
    ((3, (4, 0, 3, 1)), (0, (4, 0, 3, 1)), (2, (4, 0, 3, 1)), (1, (7, 2, 5, 6)), (2, (7, 2, 5, 6)), (0, (7, 2, 5, 6)), (3, (7, 2, 5, 6)), (1, (4, 0, 3, 1))),
    ((3, (4, 2, 6, 0)), (1, (4, 2, 6, 0)), (2, (5, 1, 3, 7)), (2, (4, 2, 6, 0)), (0, (4, 2, 6, 0)), (1, (5, 1, 3, 7)), (3, (5, 1, 3, 7)), (0, (5, 1, 3, 7))),
)
# fmt: on

# For each fingerprint nibble, most significant first: (crumb j, byte a, byte b).
OUTPUT_CRUMBS = (
    (3, 0, 6), (3, 3, 2), (3, 1, 5), (3, 4, 7), (2, 0, 6), (2, 3, 2), (2, 1, 5), (2, 4, 7),
    (1, 0, 6), (1, 3, 2), (1, 1, 5), (1, 4, 7), (0, 0, 6), (0, 3, 2), (0, 1, 5), (0, 4, 7),
)  # fmt: skip

# For each fingerprint nibble, its value for each of the 16 crumb pairs.
OUTPUT_ENCODING = tuple(
    bytes(int(nibble, 16) for nibble in table)
    for table in (
        "39fc6a4710bed285", "d3e086192cb475fa", "4813eb0752dfa9c6", "8f5ac7219d406e3b",
        "16d9f3e4ab25c870", "687c139af052dbe4", "5cb2ad73680e49f1", "d9a42f187b65e03c",
        "1c3e92d587bfa406", "218bd470a3cfe659", "14af6dbe970c5832", "2085fde91ca376b4",
        "f2d5a8961be3c704", "814e0635d9cf7ab2", "3ec4715b2680fad9", "e87d946c2a5b03f1",
    )
)  # fmt: skip


def _crumb(value: int, j: int) -> int:
    return (value >> j) & 1 | ((value >> (j + 4)) & 1) << 1


# _CRUMB_AT[j][k][v] == _crumb(v, j) << 2 * k, so a round needs only table lookups.
_CRUMB_AT = tuple(tuple(bytes(_crumb(v, j) << 2 * k for v in range(256)) for k in range(4)) for j in range(4))


def fingerprint_challenge(destination: bytearray, challenge: bytes) -> None:
    if len(destination) < FINGERPRINT_LENGTH:
        raise ValueError("destination must be at least 8 bytes")
    if len(challenge) < 18:
        raise ValueError("challenge must be at least 18 bytes")

    y = [INV_SBOX[c ^ k] for c, k in zip(challenge[2:18], INPUT_KEY)]
    state = [y[i] ^ y[i + 8] for i in range(8)]
    for keys, wiring in zip(ROUND_KEYS, ROUND_WIRING):
        new_state = []
        for key, (j, (s0, s1, s2, s3)) in zip(keys, wiring):
            c0, c1, c2, c3 = _CRUMB_AT[j]
            new_state.append(INV_SBOX[(c0[state[s0]] | c1[state[s1]] | c2[state[s2]] | c3[state[s3]]) ^ key])
        state = new_state
    for index in range(FINGERPRINT_LENGTH):
        (j, a, b), encoding = OUTPUT_CRUMBS[2 * index], OUTPUT_ENCODING[2 * index]
        high = encoding[_CRUMB_AT[j][0][state[a]] | _CRUMB_AT[j][1][state[b]]]
        (j, a, b), encoding = OUTPUT_CRUMBS[2 * index + 1], OUTPUT_ENCODING[2 * index + 1]
        low = encoding[_CRUMB_AT[j][0][state[a]] | _CRUMB_AT[j][1][state[b]]]
        destination[index] = high << 4 | low
