"""Candidate affine point encoding, including an actually reachable counterexample."""

import random
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import transform7, transform12
from tools import recover_transform7_setup as model


def test_recovered_affine_coefficients_and_inverse() -> None:
    candidate = model.recover()
    p = model.MODULUS
    fractions = (((1, 4), (1, 2), (1, 8)), ((3, 32), (5, 16), (15, 64)), ((1, 8), (1, 4), (3, 16)))
    assert candidate.matrix == tuple(tuple(n * pow(d, -1, p) % p for n, d in row) for row in fractions)
    assert candidate.offsets == (
        119837857766959630917594351638328714638160910892,
        1075284659745460397989926177318336564412678890279,
        419432502184358708211580230734150501233563188122,
    )
    inverse = model.inverse(candidate.matrix)
    assert inverse == tuple(tuple(value % p for value in row) for row in ((0, -16, 20), (3, 8, -12), (-4, 0, 8)))
    for i in range(3):
        for j in range(3):
            assert sum(candidate.matrix[i][k] * inverse[k][j] for k in range(3)) % p == int(i == j)


def test_fresh_samples_and_forced_flag_bits() -> None:
    rng = random.Random(0x716)
    candidate = model.recover()
    inputs = [(0, 0, 0), (1, 1, 1), (2, 3, 4), (model.arithmetic.MASK,) * 3]
    inputs.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(64))
    for x, y, r in inputs:
        actual = model.capture_setup(x, y, r)
        predicted = candidate.encode(x, y, r)
        assert tuple(value % model.MODULUS for value in actual[:3]) == predicted
        assert actual[3] % model.MODULUS == x % model.MODULUS
        assert candidate.decode(predicted) == (x % model.MODULUS, (y | 4) % model.MODULUS, (r | 4) % model.MODULUS)


def test_targeted_legal_base_point_probe_breaks_affine_equivalence() -> None:
    x, y, r = model.targeted_base_point_probe()
    assert r == 1456322070154714087054275448276265639382807574476
    assert r & 4 and 0 <= r < model.arithmetic.LIMIT
    expected = model.recover().encode(x, y, r)
    actual = model.capture_setup(x, y, r)
    assert expected[0] == 1 << 128
    assert actual[0] == 94
    assert actual[1:3] == expected[1:3]
    assert actual[3] == x


def test_affine_setup_substitution_changes_complete_transform7_destination() -> None:
    x, y, r = model.targeted_base_point_probe()
    source = model.TRANSFORM7_DATA[0xD8:]
    prng1, prng2 = bytearray(r.to_bytes(20, "little")), bytearray((1).to_bytes(20, "little"))
    expected, rewritten = bytearray(72), bytearray(72)
    transform7.execute(expected, prng1, prng2, source)
    original = transform12.execute
    calls = 0
    predicted = model.recover().encode(x, y, r)

    def replace_setup(context: bytearray, index: int, count: int) -> None:
        nonlocal calls
        if calls == 0:
            for slot, value in zip(model.SLOTS[:3], predicted):
                context[slot * 24 : (slot + 1) * 24] = model.arithmetic.encode(value)
        calls += 1
        original(context, index, count)

    with patch.object(transform12, "execute", replace_setup):
        transform7.execute(rewritten, prng1, prng2, source)
    assert calls == 249
    assert transform12.execute is original
    assert rewritten != expected


def test_setup_capture_restores_dispatcher() -> None:
    original = transform12.execute
    model.capture_setup(1, 2, 3)
    assert transform12.execute is original


@pytest.mark.parametrize("matrix", [(), ((0,),)])
def test_invalid_or_singular_matrix_rejected(matrix: model.Matrix) -> None:
    with pytest.raises(ValueError):
        model.inverse(matrix)


@pytest.mark.parametrize("value", [-1, model.arithmetic.LIMIT])
def test_unrepresentable_setup_inputs_rejected(value: int) -> None:
    with pytest.raises(ValueError, match="160-bit"):
        model.capture_setup(value, 0, 0)


def test_candidate_shape_checked() -> None:
    with pytest.raises(ValueError, match="3x3"):
        model.Candidate((0,), ((1,),))
