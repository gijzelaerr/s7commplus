"""Normalize the span decoder and prove a prefix of Monolith4's addition.

Exact Boolean interpretation of generated source and canonical decision diagram
comparison; no interpolation. Checkout-only, not a runtime replacement.
"""

from __future__ import annotations

import ast
import json
import struct
from collections.abc import Sequence
from functools import lru_cache

from tools.recover_monolith5 import BDD, _literal
from tools.recover_monolith5_span_decoder import MODULUS, P, Term, local_gate, recover
from tools.trace_session_auth_bits import trace_output_bits
from tools.trace_session_auth_output import REPOSITORY_ROOT, trace_monolith


@lru_cache(maxsize=18)
def _slice(word: int) -> tuple[list[tuple[str, ast.expr]], tuple[frozenset[tuple[int, int]], ...]]:
    trace = trace_monolith(4, word)
    paths = {assignment["path"] for assignment in trace["assignments"]}
    if len(paths) != 1 or any(not ref.startswith("source[") for ref in trace["inputs"]):
        raise ValueError("expected source-only Monolith4 slice")
    module = ast.parse((REPOSITORY_ROOT / next(iter(paths))).read_text(encoding="utf-8"))
    execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    wanted = {(assignment["line"], assignment["target"]) for assignment in trace["assignments"]}
    statements = []
    for statement in execute.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            name = f"dst_dwords[{_literal(target.slice)}]"
        else:
            continue
        if (statement.lineno, name) in wanted:
            statements.append((name, statement.value))
    return statements, tuple(frozenset(value) for value in trace_output_bits(4, word))


def _gate(bdd: BDD, term: Term, bits: list[int]) -> int:
    a, b, c = [
        bdd.invert(bits[member]) if term.inversions & (1 << index) else bits[member] for index, member in enumerate(term.order)
    ]
    if term.gate == "choose":
        return bdd.apply("xor", b, bdd.apply("and", bdd.apply("xor", a, b), c))
    if term.gate == "majority":
        return bdd.apply("xor", bdd.apply("xor", bdd.apply("and", a, b), bdd.apply("and", a, c)), bdd.apply("and", b, c))
    raise ValueError("unsupported gate")


@lru_cache(maxsize=4)
def _program(monolith: int = 4) -> list[tuple[str, ast.expr]]:
    if monolith not in (3, 4, 5, 6):
        raise ValueError("unsupported decoded-span monolith")
    path = REPOSITORY_ROOT / f"s7commplus/session_auth/family0/_generated/monolith{monolith}.py"
    module = ast.parse(path.read_text(encoding="utf-8"))
    execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    statements = []
    for statement in execute.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id.startswith("uVar"):
            statements.append((target.id, statement.value))
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "dst_dwords":
            statements.append((f"dst_dwords[{_literal(target.slice)}]", statement.value))
    return statements


def output_bit_diagram(word: int, bit: int, bdd: BDD, monolith: int = 4) -> int:
    """Interpret one generated output bit using the shared versioned AST DAG."""
    counts = {3: 36, 4: 18, 5: 12, 6: 36}
    if monolith not in counts or not 0 <= word < counts[monolith] or not 0 <= bit < 32:
        raise ValueError("unsupported decoded-span output")
    # One versioned evaluator per backend shares every demanded carry bit
    # across output words and decoder terms instead of rebuilding their DAGs.
    if not hasattr(bdd, "_monolith_evaluators"):
        bdd._monolith_evaluators = {}
    if monolith not in bdd._monolith_evaluators:
        statements = _program(monolith)
        bindings: list[dict[str, int]] = []
        latest: dict[str, int] = {}
        for index, (name, expression) in enumerate(statements):
            # Capture only names read by this assignment. Copying every live
            # SSA binding at every statement is quadratic and becomes costly
            # when composing many wrapper invocations in one setup DAG.
            bindings.append(
                {
                    node.id: latest[node.id]
                    for node in ast.walk(expression)
                    if isinstance(node, ast.Name) and node.id.startswith("uVar")
                }
            )
            latest[name] = index

        @lru_cache(maxsize=None)
        def evaluate(node: ast.expr, bit: int, owner: int) -> int:
            # Evaluate ONLY demanded bits. Interpreting whole words builds
            # unrelated carry diagrams under the same union of input refs.
            if not 0 <= bit < 32:
                return 0
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return (node.value >> bit) & 1
            if isinstance(node, ast.Name):
                if node.id == "_U32":
                    return 1
                index = bindings[owner][node.id]
                return evaluate(statements[index][1], bit, index)
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "src_dwords":
                ref = (_literal(node.slice), bit)
                return bdd._node(bdd.ref_index[ref], 0, 1) if ref in bdd.ref_index else 0
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
                return bdd.invert(evaluate(node.operand, bit, owner))
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_shr"
                and len(node.args) == 2
                and not node.keywords
            ):
                return evaluate(node.args[0], bit + _literal(node.args[1]), owner)
            if isinstance(node, ast.BinOp):
                # Prune masked-off branches before constructing their BDDs.
                # Those expressions may contain many irrelevant source bits.
                if isinstance(node.op, (ast.BitAnd, ast.BitOr)):
                    for operand in (node.left, node.right):
                        if isinstance(operand, ast.Constant) and type(operand.value) is int:
                            value = (operand.value >> bit) & 1
                            if isinstance(node.op, ast.BitAnd) and value == 0:
                                return 0
                            if isinstance(node.op, ast.BitOr) and value == 1:
                                return 1
                if isinstance(node.op, (ast.LShift, ast.RShift)):
                    shift = _literal(node.right)
                    return evaluate(node.left, bit - shift if isinstance(node.op, ast.LShift) else bit + shift, owner)
                if isinstance(node.op, ast.Mult):
                    multiplier = _literal(node.right)
                    if multiplier <= 0 or multiplier & (multiplier - 1):
                        raise ValueError("unsupported multiplier")
                    return evaluate(node.left, bit - multiplier.bit_length() + 1, owner)
                left, right = evaluate(node.left, bit, owner), evaluate(node.right, bit, owner)
                if isinstance(node.op, ast.BitAnd):
                    return bdd.apply("and", left, right)
                if isinstance(node.op, ast.BitXor):
                    return bdd.apply("xor", left, right)
                if isinstance(node.op, ast.BitOr):
                    return bdd.invert(bdd.apply("and", bdd.invert(left), bdd.invert(right)))
            raise ValueError(f"unsupported bit expression {ast.dump(node)}")

        bdd._monolith_evaluators[monolith] = evaluate, latest
    evaluate_bit, latest = bdd._monolith_evaluators[monolith]
    statements = _program(monolith)
    index = latest[f"dst_dwords[{word}]"]
    return evaluate_bit(statements[index][1], bit, index)


def output_gate_diagram(term: Term, bdd: BDD, monolith: int = 4, span: int = 0) -> int:
    if monolith not in (3, 4, 6) or not 0 <= span < (1 if monolith == 4 else 2):
        raise ValueError("unsupported decoded-span output")
    bits = [output_bit_diagram(span * 18 + term.chunk * 3 + member, term.bit, bdd, monolith) for member in range(3)]
    return _gate(bdd, term, bits)


def input_gate_diagram(term: Term, span: int, bdd: BDD) -> int:
    refs = [(span * 18 + term.chunk * 3 + member, term.bit) for member in range(3)]
    bits = [bdd._node(bdd.ref_index[ref], 0, 1) for ref in refs]
    return _gate(bdd, term, bits)


@lru_cache(maxsize=1)
def normalized_terms() -> tuple[Term, tuple[Term, ...]]:
    model = recover()
    boundary, *terms = model.terms
    terms.sort(key=lambda term: abs(term.weight))
    if boundary.weight != (P + 1) // 2 or [abs(term.weight) for term in terms] != [1 << bit for bit in range(168)]:
        raise ValueError("decoder is not a 168-bit binary payload plus a half-p boundary bit")
    if model.constant != -3 * sum(term.weight for term in terms if term.weight < 0):
        raise ValueError("decoder constant does not cancel the three complement offsets")
    return boundary, tuple(terms)


def normalized_span(words: Sequence[int]) -> tuple[int, int]:
    if len(words) != 18 or any(not 0 <= word <= 0xFFFFFFFF for word in words):
        raise ValueError("expected eighteen uint32 words")
    boundary, terms = normalized_terms()
    payload = sum((local_gate(term, words) ^ int(term.weight < 0)) << bit for bit, term in enumerate(terms))
    return payload, local_gate(boundary, words)


def normalized_combined(source: Sequence[int]) -> int:
    """Exact Monolith5 combined payload modulo 2^168 in normalized notation."""
    if len(source) != 54:
        raise ValueError("expected three eighteen-word spans")
    spans = [normalized_span(source[index * 18 : (index + 1) * 18]) for index in range(3)]
    boundary_sum = sum(boundary for _, boundary in spans)
    return (sum(payload for payload, _ in spans) + ((P + 1) // 2) * (boundary_sum % 2) + int(boundary_sum >= 2)) % MODULUS


def candidate_add(left: bytes, right: bytes) -> tuple[int, int, bool]:
    """Decoded addition, now fully proved by the separate carry-stage harness.

    The historical name is retained; this predicts decoded bits, not the raw
    encoded output words, and is not a runtime replacement.
    """
    if len(left) != 72 or len(right) != 72:
        raise ValueError("expected two 72-byte spans")
    a, h = normalized_span(struct.unpack("<18I", left))
    b, k = normalized_span(struct.unpack("<18I", right))
    total = a + b + (h & k)
    return total % MODULUS, h ^ k, total >= MODULUS


def prove_prefix(bits: int = 8) -> dict[str, int]:
    """Prove boundary XOR and a bounded payload prefix, NOT the entire addition."""
    if not 0 <= bits <= 168:
        raise ValueError("prefix length must be in 0..168")
    boundary, terms = normalized_terms()
    peak = 0
    for position in range(-1, bits):
        term = boundary if position == -1 else terms[position]
        refs = set().union(*(_slice(term.chunk * 3 + member)[1][term.bit] for member in range(3)))
        for earlier in (boundary, *terms[: position + 1]):
            refs.update((span * 18 + earlier.chunk * 3 + member, earlier.bit) for span in range(2) for member in range(3))
        bdd = BDD(sorted(refs, key=lambda ref: (ref[1], ref[0])))
        lb = input_gate_diagram(boundary, 0, bdd)
        rb = input_gate_diagram(boundary, 1, bdd)
        output = output_gate_diagram(term, bdd)
        if position == -1:
            expected = bdd.apply("xor", lb, rb)
        else:
            carry = bdd.apply("and", lb, rb)
            for earlier in terms[: position + 1]:
                left = input_gate_diagram(earlier, 0, bdd)
                right = input_gate_diagram(earlier, 1, bdd)
                if earlier.weight < 0:
                    left, right = bdd.invert(left), bdd.invert(right)
                expected = bdd.apply("xor", bdd.apply("xor", left, right), carry)
                carry = bdd.apply(
                    "xor",
                    bdd.apply("xor", bdd.apply("and", left, right), bdd.apply("and", left, carry)),
                    bdd.apply("and", right, carry),
                )
            if term.weight < 0:
                output = bdd.invert(output)
        if output != expected:
            raise ValueError(f"decoded ripple-addition mismatch at bit {position}")
        peak = max(peak, len(bdd.nodes) - 2)
    return {
        "proved_boundary_bits": 1,
        "proved_payload_prefix_bits": bits,
        "peak_decision_nodes": peak,
        "overflow_residue": MODULUS % P,
    }


def main() -> None:
    print(
        json.dumps(
            {
                "scope": "exact decoder normalization and bounded Monolith4 source proof; NOT a full addition proof",
                "normalized_decoder": "V = B + ((p+1)/2)*h (mod p); B is 168 ordinary binary bits",
                "exact_monolith5": "A+B = sum(Bi) + ((p+1)/2)*parity(hi) + majority(hi) (mod 2^168)",
                "candidate_monolith4": "B_out=(B0+B1+(h0&h1)) mod 2^168; h_out=h0 XOR h1",
                "candidate_shadow_correction": "-2^168 * overflow (mod p) = -12032 * overflow (mod p)",
                "proof": prove_prefix(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
