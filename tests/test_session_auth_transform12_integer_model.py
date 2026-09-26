"""Check independently derived integer equations against packed arithmetic."""

import random

import pytest

from s7commplus.session_auth.family0 import big_int_operations, big_int_transforms, transform12
from s7commplus.session_auth.family0._generated.data import TRANSFORM12_BIG_INT_DATA
from tools import transform12_integer_model as model
from tools.decompile_transform12 import CONTEXT_SLOTS, dispatch_program, phase2_program


def test_packing_matches_prepare_finalize() -> None:
    rng = random.Random(16047)
    for value in [0, 1, model.CANDIDATE_MODULUS, model.MASK, *(rng.getrandbits(160) for _ in range(1000))]:
        packed = model.encode(value)
        prepared = bytearray(20)
        finalized = bytearray(24)
        big_int_operations.prepare(prepared, packed)
        big_int_operations.finalize(finalized, value.to_bytes(20, "little"))
        assert int.from_bytes(prepared, "little") == value
        assert bytes(finalized) == packed
        assert model.decode(packed) == value


def test_independent_integer_equations() -> None:
    rng = random.Random(47160)
    boundaries = [0, 1, 46, 47, (1 << 32) - 1, 1 << 128, model.CANDIDATE_MODULUS - 1, model.CANDIDATE_MODULUS, model.MASK]
    pairs = [(a, b) for a in boundaries for b in boundaries]
    pairs.extend((rng.getrandbits(160), rng.getrandbits(160)) for _ in range(2000))
    operations = [
        (model.add, big_int_transforms.big_int_addition),
        (model.subtract, big_int_transforms.big_int_subtraction),
        (model.multiply, big_int_transforms.big_int_multiplication),
    ]
    for a, b in pairs:
        for equation, runtime in operations:
            result = bytearray(24)
            runtime(result, model.encode(a), model.encode(b))
            assert bytes(result) == model.encode(equation(a, b))
        result = bytearray(24)
        big_int_transforms.big_int_square(result, model.encode(a))
        assert bytes(result) == model.encode(model.square(a))


def test_modular_addition_counterexample() -> None:
    a, b = model.CANDIDATE_MODULUS - 1, (1 << 128) + 47
    assert 0 <= a < model.CANDIDATE_MODULUS and 0 <= b < model.CANDIDATE_MODULUS
    assert model.add(a, b) == 140
    assert (a + b) % model.CANDIDATE_MODULUS == (1 << 128) + 46
    assert model.add(a, b) % model.CANDIDATE_MODULUS != (a + b) % model.CANDIDATE_MODULUS
    # Representatives are not reduced canonically even in the ordinary case.
    assert model.add(model.CANDIDATE_MODULUS, 0) == model.CANDIDATE_MODULUS


def test_noncanonical_packing_rejected() -> None:
    for packed in [b"", b"\x01" + bytes(23), bytes(23) + b"\x80"]:
        with pytest.raises(ValueError):
            model.decode(packed)
    for value in [-1, model.LIMIT]:
        with pytest.raises(ValueError):
            model.encode(value)


def test_all_constant_rows_use_canonical_packing() -> None:
    for offset in range(0, len(TRANSFORM12_BIG_INT_DATA), 24):
        packed = TRANSFORM12_BIG_INT_DATA[offset : offset + 24]
        assert model.encode(model.decode(packed)) == packed


def test_all_dispatches_with_independent_integer_executor() -> None:
    rng = random.Random(498160)
    initial = bytearray(b"".join(model.encode(rng.getrandbits(160)) for _ in range(CONTEXT_SLOTS)))
    for dispatch in range(498):
        program = dispatch_program(dispatch)
        expected, actual = bytearray(initial), bytearray(initial)
        transform12.execute(expected, program.start, program.count)
        model.execute_program(program, actual)
        assert actual == expected, f"dispatch {dispatch}"


def test_fixed_tail_with_independent_integer_executor() -> None:
    rng = random.Random(89160)
    for _ in range(10):
        initial = bytearray(b"".join(model.encode(rng.getrandbits(160)) for _ in range(CONTEXT_SLOTS)))
        expected, actual = bytearray(initial), bytearray(initial)
        for stage in range(160, 249):
            program = dispatch_program(stage * 2 + (stage & 1))
            transform12.execute(expected, program.start, program.count)
        model.execute_program(phase2_program(), actual)
        assert actual == expected
