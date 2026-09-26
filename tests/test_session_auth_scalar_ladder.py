"""Complete scalar shadow, source-coordinate proofs, and exact defect controls."""

import random
from unittest.mock import patch

import pytest

from s7commplus.session_auth.family0 import big_int_transforms
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA, TRANSFORM12_BIG_INT_DATA
from tools import recover_scalar_curve as curve
from tools import recover_scalar_encodings as encoding
from tools import scalar_ladder_model as ladder
from tools import transform12_integer_model as exact
from tools import transform12_residue_defects as defects
from tools.decompile_transform12 import Operand
from tools.recover_scalar_shadow import MODULUS, add, substitute
from tools.recover_transform12_phase1 import execute_state, recover as stages
from tools.trace_scalar_defects import execute, reference_case
from tools.trace_transform7_setup_shadows import conditional_candidate


def modular_phase(x: int, y: int, r: int, scalar: int) -> tuple[int, int]:
    initial = conditional_candidate().encode(x, y, r) + (x % MODULUS,)
    state = dict(zip(stages()[0].inputs, initial))
    for stage in stages():
        values = {}

        def resolve(operand: Operand) -> int:
            if operand.kind == "value":
                return values[operand.index]
            if operand.kind == "input":
                return state[operand.index] % MODULUS
            offset = operand.index * 24
            return exact.decode(TRANSFORM12_BIG_INT_DATA[offset : offset + 24]) % MODULUS

        bit = scalar >> (159 - stage.index) & 1
        program = stage.choices[bit]
        for instruction in program.instructions:
            a, b = resolve(instruction.operands[0]), resolve(instruction.operands[-1])
            value = (
                a * b if instruction.operation in ("multiply", "square") else (a + b if instruction.operation == "add" else a - b)
            )
            values[instruction.value] = value % MODULUS
        state = {slot: resolve(o) for slot, o in program.outputs}
    return state[5], state[87]


def test_all_158_encodings_have_inverse_and_direct_source_identities() -> None:
    rows = encoding.recover_all()
    assert len(rows) == 158
    assert [row.stage for row in rows] == list(range(1, 159))
    assert sum(row.bit_flip for row in rows) == 78
    for row in rows:
        assert len(row.identity_quotient_sha256) == 8
        assert encoding.inverse_encoder(row.decoder) == tuple(row.outputs[s] for s in sorted(row.outputs) if s != 94)
    report = encoding.report()
    assert report["source_coordinate_identities"] == 1278
    assert report["complete_stage_encoding_sha256"] == "8ab82f15ae241c4d39446be52a49fe3a2f8f8733b8d228bb7816f333157e0d9d"
    assert len(report["generic_ladder_relation_quotient_sha256"]) == 2
    assert report["whole_runtime_equivalence"] is False


def test_first_stage_initialization_matches_generic_ladder_symbolically() -> None:
    x, y, r = curve.variables(3)
    incoming = (curve.product(x, y), y, curve.square(r), {}, x)
    expected = curve.first_stage()
    initial_encoding = encoding.initial_encoder()
    for bit, coordinates in enumerate(encoding.canonical_outputs()):
        next_coordinates = tuple(substitute(p, incoming, 3) for p in coordinates) + (x,)
        outputs = {s: substitute(poly, next_coordinates, 3) for s, poly in initial_encoding.items()}
        assert outputs == expected[bit]


def test_scalar_mask_and_descending_index_identity() -> None:
    k = encoding.scalar_xor_mask()
    assert f"{k:040x}" == "f8e62e8673b79ca477a1d36333b1c0de6c706448"
    rng = random.Random(16078)
    flips = (False,) + tuple(row.bit_flip for row in encoding.recover_all()) + (True,)
    for scalar in (0, 1, exact.MASK, k, *(rng.getrandbits(160) for _ in range(32))):
        first, second = 1, 0
        for index, flip in enumerate(flips):
            bit = (scalar >> (159 - index) & 1) ^ int(flip)
            first, second = (2 * first, first + second) if bit == 0 else (first + second, 2 * second)
        assert second == ladder.effective_scalar(scalar)
        assert first == second + 1


def test_compact_model_matches_complete_independent_modular_tape() -> None:
    rng = random.Random(1268)
    cases = [(0, 0, 0, 0), (1, 1, 1, exact.MASK), (exact.MASK,) * 4]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(4)) for _ in range(12))
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    cases.extend((x, y, 0, encoding.scalar_xor_mask() ^ n) for n in (0, 1, 2))
    for values in cases:
        assert ladder.model(*values) == modular_phase(*values)


def test_wrong_decoder_is_rejected_by_direct_source_check() -> None:
    row = encoding.recover_all()[5]
    mutated = list(row.decoder)
    mutated[0] = add(mutated[0], {(0, 0, 0, 0): 1})
    with pytest.raises(AssertionError, match="identity"):
        encoding.verify_stage(row.stage, row.inputs, tuple(mutated), row.bit_flip)
    with pytest.raises(AssertionError, match="identity"):
        encoding.verify_stage(row.stage, row.inputs, row.decoder, not row.bit_flip)


def test_noninvertible_decoder_is_rejected() -> None:
    variables = curve.variables(4)
    with pytest.raises(ValueError, match="inverse"):
        encoding.inverse_encoder((curve.square(variables[0]), *variables[1:]))


def test_residue_defect_equations_match_integer_and_packed_runtime() -> None:
    rng = random.Random(94128)
    boundaries = (0, 1, 46, 47, (1 << 128) - 48, (1 << 128) - 47, defects.P - 1, defects.P, exact.MASK)
    pairs = [(a, b) for a in boundaries for b in boundaries]
    pairs.extend((rng.getrandbits(160), rng.getrandbits(160)) for _ in range(256))
    for name in ("add", "subtract", "multiply"):
        operation = getattr(defects, name)
        native = getattr(
            big_int_transforms,
            {"add": "big_int_addition", "subtract": "big_int_subtraction", "multiply": "big_int_multiplication"}[name],
        )
        for a, b in pairs:
            result = operation(a, b)
            assert result.representative == getattr(exact, name)(a, b)
            assert result.residue == result.representative % defects.P
            destination = bytearray(24)
            native(destination, exact.encode(a), exact.encode(b))
            assert bytes(destination) == exact.encode(result.representative)


def test_addition_and_subtraction_defects_are_explicit() -> None:
    result = defects.add(defects.P - 2, (1 << 128) + 48)
    assert result.representative == 140
    assert result.correction == 94 - (1 << 128)
    result = defects.subtract(0, exact.MASK)
    assert result.representative == defects.P + 1
    assert result.correction == 47
    assert result.residue != (0 - exact.MASK) % defects.P


@pytest.mark.parametrize("n", [0, 1, 2])
def test_reachable_on_curve_representation_defects(n: int) -> None:
    result = reference_case(n)
    assert result["defect_count"] > 0
    assert result["tail_residues_match"] is False
    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    assert result["tail_actual"] == execute_state(curve.setup(x, y, 0).slots, result["selector"])
    z, numerator = result["tail_actual"]
    shadow_z, shadow_n = result["tail_shadow"]
    if n == 0:
        assert z == defects.P and shadow_z == 0
        assert result["ordinary_inverse_precondition_holds"] is False
        assert result["defects"][0]["stage"] == 79
        assert result["defects"][0]["tape_index"] == 36796
    else:
        # These cases preserve the point, but NOT its required representatives.
        assert numerator * pow(z % defects.P, -1, defects.P) % defects.P == shadow_n * pow(shadow_z, -1, defects.P) % defects.P


def test_new_models_do_not_call_runtime_or_old_integer_arithmetic() -> None:
    with (
        patch.object(exact, "add", side_effect=AssertionError("native integer arithmetic not allowed")),
        patch.object(exact, "subtract", side_effect=AssertionError("native integer arithmetic not allowed")),
        patch.object(exact, "multiply", side_effect=AssertionError("native integer arithmetic not allowed")),
    ):
        assert execute(0, 0, 0, 0)[0]
        assert ladder.model(0, 0, 0, 0)


def test_correct_affine_point_and_zero_lift_do_not_restore_complete_output_bytes() -> None:
    from tools.recover_transform12_formulas import compact_outputs
    from tools.transform7_reference import finalize, tail_program

    x = int.from_bytes(TRANSFORM7_DATA[0xD8:0xEC], "little")
    y = int.from_bytes(TRANSFORM7_DATA[0xEC:0x100], "little")
    for n in (0, 1, 2):
        selector = encoding.scalar_xor_mask() ^ n
        actual, _ = execute(x, y, 0, selector)
        shadow = ladder.model(x, y, 0, selector)
        program = tail_program()
        context = bytearray(program.context_slots * 24)
        for slot, value in zip((5, 87), actual):
            context[slot * 24 : (slot + 1) * 24] = exact.encode(value)
        exact.execute_program(program, context)
        outputs = {slot: exact.decode(bytes(context[slot * 24 : (slot + 1) * 24])) for slot, _ in program.outputs}
        candidate = compact_outputs(*shadow)
        assert finalize(outputs) != finalize(candidate)
        lifted = {slot: (defects.P if value == 0 and slot in (61, 97) else value) for slot, value in candidate.items()}
        assert (finalize(outputs) == finalize(lifted)) == (n == 0)


def test_optional_source_ast_defect_proofs_and_translation_controls() -> None:
    z3 = pytest.importorskip("z3")
    from tools.prove_transform12_residue_defects import WIDTH, compile_source, prove

    rng = random.Random(322)
    for operation in ("add", "subtract", "multiply"):
        for _ in range(16):
            a, b = rng.getrandbits(160), rng.getrandbits(160)
            result = compile_source(z3, operation, z3.BitVecVal(a, WIDTH), z3.BitVecVal(b, WIDTH))
            assert z3.simplify(result).as_long() == getattr(exact, operation)(a, b)
    # Use the CLI's bounded proof budget, not a timing-sensitive 3s limit.
    # UNKNOWN remains a failure; only all six UNSAT obligations pass.
    report = prove()
    assert report["full_proof"], report["obligations"]
    assert len(report["obligations"]) == 6


@pytest.mark.parametrize("value", [-1, exact.LIMIT])
def test_invalid_domain_rejected(value: int) -> None:
    with pytest.raises(ValueError, match="160-bit"):
        ladder.model(value, 0, 0, 0)
    with pytest.raises(ValueError, match="160-bit"):
        defects.add(value, 0)
