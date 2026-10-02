"""Recover the SPN behind HarpoS7's fingerprint gate network.

HarpoS7's fingerprint (``old/family0/fingerprint.py``) is a fixed network of
496 nibble gates: a white-boxed cipher whose wires carry secret 4-bit
encodings. This tool recovers the cipher from the network alone and checks
that the constants in ``s7commplus/v1_session_key/real_plc/fingerprint.py``
match. With ``--print`` it prints the recovered constants instead.

Write ``crumb(v, j)`` for bits ``j`` and ``j + 4`` of byte ``v``, as a 2-bit
value. The recovery proceeds layer by layer, labelling every wire nibble with
the two plain crumbs it determines:

1. Layer 1 reads the challenge unencoded. For each challenge byte there is
   exactly one key byte ``k`` for which every output nibble determines two
   crumbs of ``InvSbox(c ^ k)``.
2. Shuffle layers (each output nibble reads 2 bits of each input nibble)
   only route crumbs; each output is labelled with the input crumbs it
   determines.
3. The fold layer's outputs determine the XOR of crumb ``j`` of bytes ``i``
   and ``i + 8``.
4. Each remaining gate pair is an 8-bit S-box reading crumb ``j`` of four
   bytes. Exactly one source order and key byte make both output nibbles
   determine two crumbs of ``InvSbox(input ^ k)``.
5. Each fingerprint nibble determines crumb ``j`` of two final bytes; the
   nibble is a fixed 4-bit encoding of those 4 bits.

Every step asserts a unique match; the recovered model is then compared with
the gate network on random challenges.
"""

from __future__ import annotations

import argparse
import itertools
import random
import sys
from collections import defaultdict
from dataclasses import dataclass

from old.family0 import fingerprint as harpo
from s7commplus.v1_session_key.real_plc import fingerprint as runtime

# Final-state nibbles HarpoS7 reads the fingerprint from, most significant first.
OUTPUT_NIBBLES = (187, 448, 378, 107, 239, 173, 166, 66, 458, 117, 138, 331, 126, 178, 344, 495)

Gate = tuple[int, int, int, bytes]
Label = tuple[str, int]  # (byte variable, crumb index j)
Meaning = list[tuple[Label, dict[int, int]]]  # per wire nibble: crumb label -> {encoded nibble: crumb value}


def crumb(value: int, j: int) -> int:
    return (value >> j) & 1 | ((value >> (j + 4)) & 1) << 1


@dataclass
class Recovered:
    input_key: bytes
    round_keys: list[bytes]
    round_wiring: list[list[tuple[int, tuple[int, int, int, int]]]]
    output: list[tuple[int, int, int]]
    output_encoding: list[bytes]


def _layers(network: list[Gate]) -> dict[int, list[int]]:
    depth = [0] * 544
    layers: dict[int, list[int]] = defaultdict(list)
    for index, (a, b, dst, _) in enumerate(network):
        depth[dst] = max(depth[a], depth[b]) + 1
        layers[depth[dst]].append(index)
    return layers


def _determined(table: bytes, candidates: dict[Label, list[int]]) -> Meaning:
    """The candidate crumbs (given as values over all 256 gate inputs) that ``table`` determines."""
    result: Meaning = []
    for label, values in candidates.items():
        mapping: dict[int, int] = {}
        if all(mapping.setdefault(table[xy], values[xy]) == values[xy] for xy in range(256)):
            result.append((label, mapping))
    return result


def _input_crumbs(meaning: dict[int, Meaning], a: int, b: int) -> dict[Label, list[int]]:
    """Every crumb carried by nibbles ``a`` and ``b``, as its value for each gate input ``a << 4 | b``."""
    crumbs = {}
    for label, mapping in meaning[a]:
        crumbs[label] = [mapping[xy >> 4] for xy in range(256)]
    for label, mapping in meaning[b]:
        crumbs[label] = [mapping[xy & 15] for xy in range(256)]
    return crumbs


def _sbox_output(table: bytes, outputs: list[int]) -> Meaning | None:
    """Two crumbs of the S-box ``outputs`` determined by ``table``, or ``None``."""
    alive = set(range(4))
    first: dict[int, int] = {}
    for xy in range(256):
        u, g = table[xy], outputs[xy]
        if u not in first:
            first[u] = g
        else:
            alive = {j for j in alive if crumb(first[u], j) == crumb(g, j)}
            if len(alive) < 2:
                return None
    if len(alive) != 2:
        return None
    return [((" ", j), {u: crumb(g, j) for u, g in first.items()}) for j in sorted(alive)]


def recover(network: list[Gate]) -> Recovered:
    layers = _layers(network)
    assert sorted(layers) == list(range(1, 30)), "unexpected layer count"
    inv_sbox = inv_sbox_table()
    meaning: dict[int, Meaning] = {}

    # Layer 1: keyed InvSubBytes on the unencoded challenge bytes.
    input_key = bytearray(16)
    for index in layers[1]:
        a, b, dst, table = network[index]
        assert a % 2 == 0 and b == a + 1
        byte = a // 2
        hits = []
        for key in range(256):
            y = [inv_sbox[p ^ key] for p in range(256)]
            found = _determined(table, {(f"y{byte}", j): [crumb(v, j) for v in y] for j in range(4)})
            if len(found) == 2:
                hits.append((key, found))
        assert len(hits) == 1, f"layer 1 byte {byte}: {len(hits)} keys"
        input_key[byte], meaning[dst] = hits[0]

    # Layer 2 shuffles crumbs; layer 3 folds bytes i and i + 8.
    for index in layers[2]:
        a, b, dst, table = network[index]
        meaning[dst] = _determined(table, _input_crumbs(meaning, a, b))
        assert len(meaning[dst]) == 2
    for index in layers[3]:
        a, b, dst, table = network[index]
        crumbs = _input_crumbs(meaning, a, b)
        folded = {}
        for (var1, j1), values1 in crumbs.items():
            for (var2, j2), values2 in crumbs.items():
                if j1 == j2 and int(var2[1:]) == int(var1[1:]) + 8:
                    folded[(f"z{var1[1:]}", j1)] = [v1 ^ v2 for v1, v2 in zip(values1, values2)]
        meaning[dst] = _determined(table, folded)
        assert len(meaning[dst]) == 2

    # Layers 4..29 alternate S-box layers and shuffles.
    names = {f"z{i}": i for i in range(8)}
    round_keys: list[bytes] = []
    round_wiring: list[list[tuple[int, tuple[int, int, int, int]]]] = []
    for layer in range(4, 30):
        if layer % 2 == 1:
            for index in layers[layer]:
                a, b, dst, table = network[index]
                meaning[dst] = _determined(table, _input_crumbs(meaning, a, b))
                assert len(meaning[dst]) == 2
            continue
        pairs: dict[tuple[int, int], list[int]] = defaultdict(list)
        for index in layers[layer]:
            pairs[network[index][:2]].append(index)
        assert len(pairs) == 8 and all(len(p) == 2 for p in pairs.values())
        keys = bytearray(8)
        wiring = []
        new_names = {}
        for s, ((a, b), indices) in enumerate(pairs.items()):
            crumbs = _input_crumbs(meaning, a, b)
            (j,) = {label[1] for label in crumbs}
            assert len(crumbs) == 4
            hits = []
            for order in itertools.permutations(crumbs):
                w = [sum(crumbs[label][xy] << (2 * k) for k, label in enumerate(order)) for xy in range(256)]
                for key in range(256):
                    g = [inv_sbox[v ^ key] for v in w]
                    outs = [_sbox_output(network[i][3], g) for i in indices]
                    if all(outs):
                        hits.append((order, key, outs))
            assert len(hits) == 1, f"layer {layer} S-box {s}: {len(hits)} matches"
            order, key, outs = hits[0]
            name = f"r{layer}s{s}"
            keys[s] = key
            wiring.append((j, tuple(names[label[0]] for label in order)))
            for i, out in zip(indices, outs):
                assert out is not None
                meaning[network[i][2]] = [((name, jj), m) for (_, jj), m in out]
            new_names[name] = s
        names = new_names
        round_keys.append(bytes(keys))
        round_wiring.append(wiring)  # type: ignore[arg-type]

    # Output: each nibble determines crumb j of two final bytes.
    output = []
    encoding = []
    for nibble in OUTPUT_NIBBLES:
        (la, ma), (lb, mb) = meaning[nibble]
        assert la[1] == lb[1]
        output.append((la[1], names[la[0]], names[lb[0]]))
        table = bytearray(16)
        for u in range(16):
            table[ma[u] | mb[u] << 2] = u
        encoding.append(bytes(table))
    return Recovered(bytes(input_key), round_keys, round_wiring, output, encoding)


def inv_sbox_table() -> list[int]:
    """AES's inverse S-box, computed from GF(2^8) inversion so the tool trusts no table."""

    def mul(a: int, b: int) -> int:
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = (a << 1) ^ (0x11B if a & 0x80 else 0)
            b >>= 1
        return r

    sbox = [0] * 256
    for x in range(256):
        inv = next((y for y in range(1, 256) if mul(x, y) == 1), 0)
        r = 0x63
        for i in range(8):
            r ^= (
                ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8)))
                & 1
            ) << i
        sbox[x] = r
    inverse = [0] * 256
    for x, y in enumerate(sbox):
        inverse[y] = x
    return inverse


def evaluate(recovered: Recovered, challenge: bytes) -> bytes:
    inv_sbox = inv_sbox_table()
    y = [inv_sbox[c ^ k] for c, k in zip(challenge[2:18], recovered.input_key)]
    state = [y[i] ^ y[i + 8] for i in range(8)]
    for keys, wiring in zip(recovered.round_keys, recovered.round_wiring):
        state = [
            inv_sbox[sum(crumb(state[src], j) << (2 * k) for k, src in enumerate(sources)) ^ key]
            for key, (j, sources) in zip(keys, wiring)
        ]
    nibbles = [
        enc[crumb(state[a], j) | crumb(state[b], j) << 2] for (j, a, b), enc in zip(recovered.output, recovered.output_encoding)
    ]
    return bytes(nibbles[2 * i] << 4 | nibbles[2 * i + 1] for i in range(8))


def _runtime_constants() -> Recovered:
    return Recovered(
        runtime.INPUT_KEY,
        list(runtime.ROUND_KEYS),
        [list(w) for w in runtime.ROUND_WIRING],
        list(runtime.OUTPUT_CRUMBS),
        list(runtime.OUTPUT_ENCODING),
    )


def _format(recovered: Recovered) -> str:
    lines = [f"INPUT_KEY = bytes.fromhex({recovered.input_key.hex()!r})", "ROUND_KEYS = ("]
    lines += [f"    bytes.fromhex({k.hex()!r})," for k in recovered.round_keys]
    lines += [")", "ROUND_WIRING = ("]
    lines += [f"    {tuple(w)!r}," for w in recovered.round_wiring]
    lines += [")", f"OUTPUT_CRUMBS = {tuple(recovered.output)!r}", "OUTPUT_ENCODING tables:"]
    lines += [f"    {''.join(f'{n:x}' for n in e)!r}," for e in recovered.output_encoding]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print", action="store_true", help="print the recovered constants")
    args = parser.parse_args()
    network = harpo.gates()
    recovered = recover(network)
    rng = random.Random(4602)
    for _ in range(500):
        challenge = rng.randbytes(18)
        assert evaluate(recovered, challenge) == harpo.evaluate(network, challenge), "recovered model disagrees"
    if args.print:
        print(_format(recovered))
        return 0
    if recovered != _runtime_constants():
        print(
            "fingerprint.py constants differ from the recovery; run python -m tools.recover_fingerprint --print", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
