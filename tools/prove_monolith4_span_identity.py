"""Optional Z3 proof of all decoded Monolith4 output bits from generated AST.

Install the checkout-only `analysis` extra. A timeout/unknown is NOT a proof.
No generated runtime helpers are used to construct the symbolic equations.
"""

from __future__ import annotations

import ast
import argparse
import hashlib
import json
import random
import struct
import time
from pathlib import Path
from typing import Any

from s7commplus.session_auth.family0._generated import monolith3, monolith4, monolith5, monolith6
from tools.recover_monolith4_span_identity import input_gate_diagram, normalized_span, normalized_terms, output_gate_diagram
from tools.recover_monolith5 import _literal


def symbolic_source(number: int = 4) -> tuple[Any, list[Any], list[Any]]:
    modules = {3: (monolith3, 42, 36), 4: (monolith4, 36, 18), 5: (monolith5, 54, 12), 6: (monolith6, 54, 36)}
    if number not in modules:
        raise ValueError("unsupported decoded-span monolith")
    module_source, source_count, destination_count = modules[number]
    try:
        import z3
    except ImportError as error:
        raise RuntimeError("install the development-only analysis extra to run this proof") from error
    path = Path(module_source.__file__)
    module = ast.parse(path.read_text(encoding="utf-8"))
    constants = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_U32"
    ]
    if len(constants) != 1 or _literal(constants[0].value) != 0xFFFFFFFF:
        raise ValueError("unexpected uint32 mask")
    shift = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "_shr")
    if not isinstance(shift.body[-1], ast.Return) or ast.dump(shift.body[-1].value) != ast.dump(
        ast.parse("(x & _U32) >> n", mode="eval").body
    ):
        raise ValueError("unexpected logical-shift helper")
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    source = [z3.BitVec(f"source_{word}", 32) for word in range(source_count)]
    values: dict[str, Any] = {}
    destination: dict[int, Any] = {}

    def expression(node: ast.expr) -> Any:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return z3.BitVecVal(node.value, 32)
        if isinstance(node, ast.Name):
            return z3.BitVecVal(0xFFFFFFFF, 32) if node.id == "_U32" else values[node.id]
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "src_dwords":
            return source[_literal(node.slice)]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return ~expression(node.operand)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_shr"
            and len(node.args) == 2
            and not node.keywords
        ):
            return z3.LShR(expression(node.args[0]), _literal(node.args[1]))
        if isinstance(node, ast.BinOp):
            left = expression(node.left)
            if isinstance(node.op, ast.LShift):
                return left << _literal(node.right)
            if isinstance(node.op, ast.RShift):
                return z3.LShR(left, _literal(node.right))
            if isinstance(node.op, ast.Mult):
                multiplier = _literal(node.right)
                if multiplier <= 0 or multiplier & (multiplier - 1):
                    raise ValueError("unsupported multiplier")
                return left * z3.BitVecVal(multiplier, 32)
            right = expression(node.right)
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
        raise ValueError(f"unsupported source expression {ast.dump(node)}")

    for statement in function.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            raise ValueError("unexpected generated statement")
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            if target.id in {"src_dwords", "dst_dwords"}:
                expected = "_to_uints(source)" if target.id == "src_dwords" else "_to_uints(destination)"
                if ast.dump(statement.value) != ast.dump(ast.parse(expected, mode="eval").body):
                    raise ValueError("unexpected word-loading prologue")
                continue
            if not target.id.startswith("uVar"):
                raise ValueError("unexpected generated variable")
            # Preserve the generated DAG; simplifying every assignment can
            # expand intermediate bitvector terms long before solver timeout.
            values[target.id] = expression(statement.value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            index = _literal(target.slice)
            if index in destination:
                raise ValueError("repeated destination assignment")
            destination[index] = expression(statement.value)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "destination":
            # Generated byte writeback; destination words were constructed above.
            expected_writeback = ast.parse("destination[: len(dst_dwords) * 4] = _from_uints(dst_dwords)").body[0]
            if ast.dump(statement) != ast.dump(expected_writeback):
                raise ValueError("unexpected writeback")
        else:
            raise ValueError("unexpected generated assignment")
    if set(destination) != set(range(destination_count)):
        raise ValueError("expected every output word")
    return z3, source, [destination[word] for word in range(destination_count)]


def boolean_backend(z3: Any, source_words: int = 36) -> Any:
    """Reusable demanded-bit backend for prefix and carry-stage proofs."""
    if source_words <= 0:
        raise ValueError("expected positive source word count")

    class Backend:
        def __init__(self) -> None:
            self.refs = [(word, bit) for word in range(source_words) for bit in range(32)]
            self.ref_index = {ref: index for index, ref in enumerate(self.refs)}
            self.variables = [z3.Bool(f"bit_{word}_{bit}") for word, bit in self.refs]

        @staticmethod
        def value(node: Any) -> Any:
            return z3.BoolVal(bool(node)) if type(node) is int else node

        def _node(self, variable: int, low: int, high: int) -> Any:
            if (low, high) != (0, 1):
                raise ValueError("expected plain source selector")
            return self.variables[variable]

        def invert(self, node: Any) -> Any:
            return z3.Not(self.value(node))

        def apply(self, operation: str, left: Any, right: Any) -> Any:
            left, right = self.value(left), self.value(right)
            if operation == "and":
                return z3.And(left, right)
            if operation == "xor":
                return z3.Xor(left, right)
            raise ValueError("unsupported Boolean operation")

    return Backend()


def prove(timeout_ms: int = 60000, payload_bits: int = 168) -> dict[str, Any]:
    if timeout_ms <= 0:
        raise ValueError("timeout must be positive")
    if not 1 <= payload_bits <= 168:
        raise ValueError("payload bits must be in 1..168")
    z3, source, output = symbolic_source()
    boundary, terms = normalized_terms()
    backend = boolean_backend(z3)
    lb = input_gate_diagram(boundary, 0, backend)
    rb = input_gate_diagram(boundary, 1, backend)
    actual_boundary = output_gate_diagram(boundary, backend)
    mismatches = [z3.Xor(actual_boundary, z3.Xor(lb, rb))]
    actual_bits = []
    carry = z3.And(lb, rb)
    for term in terms[:payload_bits]:
        left = input_gate_diagram(term, 0, backend)
        right = input_gate_diagram(term, 1, backend)
        actual = output_gate_diagram(term, backend)
        if term.weight < 0:
            left, right, actual = z3.Not(left), z3.Not(right), z3.Not(actual)
        expected = z3.Xor(z3.Xor(left, right), carry)
        mismatches.append(z3.Xor(actual, expected))
        actual_bits.append(actual)
        carry = z3.Or(z3.And(left, right), z3.And(left, carry), z3.And(right, carry))
    verify_translation(z3, source, output, backend, actual_boundary, actual_bits)
    solver = z3.SolverFor("QF_FD")
    # Incremental cuts: retain only equalities already proved UNSAT for all
    # source assignments. These are derived lemmas, not input assumptions.
    deadline = time.monotonic() + timeout_ms / 1000
    checked = 0
    result = z3.unknown
    for index, mismatch in enumerate(mismatches):
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            break
        solver.set(timeout=remaining)
        query = z3.Bool(f"query_{index}")
        solver.add(query == z3.simplify(mismatch))
        result = solver.check(query)
        if result != z3.unsat:
            break
        solver.add(z3.Not(mismatch))
        checked += 1
    proved = checked == len(mismatches)
    report = {
        "scope": "all uint32 inputs, decoded output prefix and boundary relative to pinned generated AST and gate model",
        "payload_bits": payload_bits,
        "source_sha256": hashlib.sha256(Path(monolith4.__file__).read_bytes()).hexdigest(),
        "gate_model_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("monolith5_model.json", "monolith5_gate_model.json")
        },
        "z3_version": z3.get_version_string(),
        "backend": "demanded Boolean bits, independently controlled by fixed-width AST translation",
        "translation_controls": 8,
        "result": str(result),
        "checked_output_bits": checked,
        "proved": proved,
        "timeout_ms": timeout_ms,
    }
    if not proved and result != z3.sat:
        report["result"] = "unknown"
        report["reason"] = solver.reason_unknown() if result == z3.unknown else "total solver budget exhausted"
    if result == z3.sat:
        model = solver.model()
        report["counterexample"] = [
            sum(
                int(z3.is_true(model.eval(backend.variables[word * 32 + bit], model_completion=True))) << bit for bit in range(32)
            )
            for word in range(36)
        ]
    return report


def verify_translation(z3: Any, source: list[Any], output: list[Any], backend: Any, boundary_bit: Any, bits: list[Any]) -> int:
    """Replay both independent symbolic compilers against generated uint32 output."""
    packed = z3.Concat(*[z3.If(bit, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)) for bit in (boundary_bit, *reversed(bits))])
    rng = random.Random(0x4A57)
    for _ in range(8):
        words = [rng.getrandbits(32) for _ in range(36)]
        generated = bytearray(72)
        monolith4.execute(generated, struct.pack("<36I", *words))
        substitutions = [(variable, z3.BitVecVal(word, 32)) for variable, word in zip(source, words)]
        evaluated = [z3.simplify(z3.substitute(value, *substitutions)).as_long() for value in output]
        if struct.pack("<18I", *evaluated) != generated:
            raise ValueError("fixed-width translation disagrees with generated code")
        boolean_values = [
            (variable, z3.BoolVal(bool((words[word] >> bit) & 1)))
            for (word, bit), variable in zip(backend.refs, backend.variables)
        ]
        actual = z3.simplify(z3.substitute(packed, *boolean_values)).as_long()
        payload, h = normalized_span(struct.unpack("<18I", generated))
        if actual != (h << len(bits)) | (payload & ((1 << len(bits)) - 1)):
            raise ValueError("demanded-bit translation disagrees with generated code")
    return 8


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-ms", type=int, default=60000)
    parser.add_argument("--payload-bits", type=int, default=168)
    args = parser.parse_args()
    report = prove(args.timeout_ms, args.payload_bits)
    print(json.dumps(report, indent=2))
    if not report["proved"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
