"""Symbolic identities and explicit limits of the modular shadow."""

import random

import pytest

from s7commplus.session_auth.family0 import transform12
from tools import recover_transform12_formulas as formulas
from tools import transform12_integer_model as exact
from tools.decompile_transform12 import dispatch_program, phase2_program, trace_outputs


def test_exact_sparse_polynomial_recovery() -> None:
    outputs, peak = formulas.recover()
    p = formulas.MODULUS
    exponent = (p - 1) // 2 - 40
    assert peak == 75
    assert outputs[61] == {(exponent, 1): 1}
    assert outputs[71] == {(0, 1): 1}
    assert outputs[97] == {(79, 1): 1, (exponent + 79, 0): 1}
    constants = dict(
        zip(
            (480, 481, 482, 483),
            (
                377161712859587849859015440700976263137014849788,
                754323425719175699718030881401952526274029699576,
                1272920780901108993274177112365794888087425118037,
                1297740232864288696342124987470635009509738026870,
            ),
        )
    )
    assert outputs[27] == {
        (0, 0): constants[483],
        (p - 2, 1): constants[482],
        (79, 1): constants[481],
        (exponent + 79, 0): constants[481],
        (exponent, 1): constants[480],
    }


def test_compact_formulas_match_symbolic_polynomials_and_modular_tape() -> None:
    outputs, _ = formulas.recover()
    program = trace_outputs(phase2_program(), list(formulas.FINAL_SLOTS))
    p = formulas.MODULUS
    rng = random.Random(200075)
    pairs = [(0, 0), (0, 1), (1, 1), (2, 3), (p - 1, p - 1)]
    pairs.extend((rng.randrange(p), rng.randrange(p)) for _ in range(64))
    for x, y in pairs:
        values = {}

        def resolve(operand):
            if operand.kind == "value":
                return values[operand.index]
            if operand.kind == "input":
                return x if operand.index == 5 else y
            offset = operand.index * 24
            return exact.decode(formulas.TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % p

        for instruction in program.instructions:
            a = resolve(instruction.operands[0])
            b = resolve(instruction.operands[-1])
            if instruction.operation == "add":
                result = a + b
            elif instruction.operation == "subtract":
                result = a - b
            else:
                result = a * b
            values[instruction.value] = result % p
        expected = {slot: resolve(operand) for slot, operand in program.outputs}
        assert formulas.compact_outputs(x, y) == expected
        assert {slot: formulas.evaluate(poly, x, y) for slot, poly in outputs.items()} == expected


def test_shadow_is_not_a_runtime_replacement_even_for_small_inputs() -> None:
    context = bytearray(transform12.CONTEXT_SIZE)
    context[5 * 24 : 6 * 24] = exact.encode(1)
    context[87 * 24 : 88 * 24] = exact.encode(1)
    for stage in range(160, 249):
        program = dispatch_program(stage * 2)
        transform12.execute(context, program.start, program.count)
    actual = {slot: exact.decode(bytes(context[slot * 24 : (slot + 1) * 24])) % formulas.MODULUS for slot in formulas.FINAL_SLOTS}
    shadow = formulas.compact_outputs(1, 1)
    assert actual[71] == shadow[71] == 1
    assert all(actual[slot] != shadow[slot] for slot in (27, 61, 97))


def test_subtraction_witness_from_fixed_tail() -> None:
    p = formulas.MODULUS
    witness = formulas.first_divergence(1, 1)
    assert witness == formulas.Divergence(429, 34725, "subtract", (2, p + 3), exact.MASK, p - 1)
    assert formulas.first_divergence(2, 3) is None
    # At SSA v429 for x=y=1: v426=2 and v417=p+3.
    assert exact.subtract(2, p + 3) == exact.MASK
    assert exact.subtract(2, p + 3) % p == 46
    assert (2 - (p + 3)) % p == p - 1


@pytest.mark.parametrize("limit", [0, 1])
def test_term_limits_prevent_unbounded_expansion(limit: int) -> None:
    with pytest.raises(ValueError, match="limit"):
        formulas.recover(term_limit=limit)
