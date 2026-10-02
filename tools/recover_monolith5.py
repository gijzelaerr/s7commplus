"""Recover and verify the compact, analysis-only Monolith5 Boolean model.

The generated monolith is parsed into exact reduced ordered binary decision
diagrams (ROBDDs). Their unique algebraic normal forms are separated into
nine-input bit-lane functions. No solver or probabilistic equivalence claim is
needed: the derivation checks every supported uint32 operation symbolically.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import TypeAlias, TypedDict

from tools.trace_v1_session_key_bits import trace_output_bits
from tools.trace_v1_session_key_output import REPOSITORY_ROOT, trace_monolith

Word: TypeAlias = tuple[int, ...]
Polynomial: TypeAlias = frozenset[int]  # XOR of monomials; each monomial is a bitset of source-bit IDs.
Component: TypeAlias = tuple[int, int, int]  # Source triplet, bit position, nine-input LUT index.
Entry: TypeAlias = tuple[int, list[Component], int, Component | None]


class Model(TypedDict):
    version: int
    luts: list[str]
    entries: list[Entry]


class BDD:
    """Small canonical Boolean engine with an exact 0/1 terminal pair."""

    def __init__(self, refs: list[tuple[int, int]]) -> None:
        self.refs = refs
        self.ref_index = {ref: index for index, ref in enumerate(refs)}
        self.nodes: list[tuple[int, int, int]] = [(-1, 0, 0), (-1, 1, 1)]
        self.unique: dict[tuple[int, int, int], int] = {}
        self.apply_cache: dict[tuple[str, int, int], int] = {}
        self.not_cache: dict[int, int] = {}
        self.anf_cache: dict[int, Polynomial] = {}

    def _node(self, variable: int, low: int, high: int) -> int:
        if low == high:
            return low
        key = (variable, low, high)
        if key not in self.unique:
            self.unique[key] = len(self.nodes)
            self.nodes.append(key)
            if len(self.nodes) > 2_000_000:
                raise ValueError("Monolith5 BDD node limit exceeded")
        return self.unique[key]

    def _level(self, node: int) -> int:
        return len(self.refs) if node < 2 else self.nodes[node][0]

    def invert(self, node: int) -> int:
        if node < 2:
            return 1 - node
        if node not in self.not_cache:
            variable, low, high = self.nodes[node]
            self.not_cache[node] = self._node(variable, self.invert(low), self.invert(high))
        return self.not_cache[node]

    def apply(self, operation: str, left: int, right: int) -> int:
        if left > right:
            left, right = right, left
        key = (operation, left, right)
        if key in self.apply_cache:
            return self.apply_cache[key]
        if operation == "and":
            if left == 0:
                return 0
            if left == 1 or left == right:
                return right
        elif operation == "xor":
            if left == 0:
                return right
            if left == right:
                return 0
            if left == 1:
                return self.invert(right)
        else:
            raise ValueError(f"unsupported BDD operation {operation}")
        variable = min(self._level(left), self._level(right))

        def child(node: int, branch: int) -> int:
            return self.nodes[node][branch] if self._level(node) == variable else node

        result = self._node(
            variable,
            self.apply(operation, child(left, 1), child(right, 1)),
            self.apply(operation, child(left, 2), child(right, 2)),
        )
        self.apply_cache[key] = result
        return result

    def constant(self, value: int) -> Word:
        return tuple((value >> bit) & 1 for bit in range(32))

    def expression(self, node: ast.expr, values: dict[str, Word]) -> Word:
        """Symbolically interpret only the uint32 subset used by Monolith5."""
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return self.constant(node.value)
        if isinstance(node, ast.Name):
            if node.id == "_U32":
                return self.constant(0xFFFFFFFF)
            if node.id not in values:
                raise ValueError(f"unassigned {node.id} at line {node.lineno}")
            return values[node.id]
        if isinstance(node, ast.Subscript):
            if not isinstance(node.value, ast.Name) or node.value.id != "src_dwords":
                raise ValueError(f"unsupported indexed input at line {node.lineno}")
            index = _literal(node.slice)
            return tuple(
                self._node(self.ref_index[(index, bit)], 0, 1) if (index, bit) in self.ref_index else 0 for bit in range(32)
            )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return tuple(self.invert(value) for value in self.expression(node.operand, values))
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id != "_shr" or len(node.args) != 2 or node.keywords:
                raise ValueError(f"unsupported call at line {node.lineno}")
            return _shift(self.expression(node.args[0], values), _literal(node.args[1]), left=False)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.LShift, ast.RShift)):
                return _shift(self.expression(node.left, values), _literal(node.right), isinstance(node.op, ast.LShift))
            if isinstance(node.op, ast.Mult):
                multiplier = _literal(node.right)
                if multiplier <= 0 or multiplier & (multiplier - 1):
                    raise ValueError(f"non-power-of-two multiplier at line {node.lineno}")
                return _shift(self.expression(node.left, values), multiplier.bit_length() - 1, left=True)
            left, right = self.expression(node.left, values), self.expression(node.right, values)
            if isinstance(node.op, ast.BitAnd):
                return tuple(self.apply("and", a, b) for a, b in zip(left, right))
            if isinstance(node.op, ast.BitXor):
                return tuple(self.apply("xor", a, b) for a, b in zip(left, right))
            if isinstance(node.op, ast.BitOr):
                return tuple(self.invert(self.apply("and", self.invert(a), self.invert(b))) for a, b in zip(left, right))
        raise ValueError(f"unsupported expression {type(node).__name__} at line {node.lineno}")

    def anf(self, node: int) -> Polynomial:
        """Unique algebraic normal form of one BDD node."""
        if node == 0:
            return frozenset()
        if node == 1:
            return frozenset({0})
        if node in self.anf_cache:
            return self.anf_cache[node]
        variable, low, high = self.nodes[node]
        low_poly = self.anf(low)
        difference = low_poly ^ self.anf(high)
        result = low_poly ^ frozenset(term | (1 << variable) for term in difference)
        self.anf_cache[node] = result
        return result

    def source_polynomial(self, node: int) -> Polynomial:
        """Translate local BDD variables to global (word * 32 + bit) IDs."""
        translated: set[int] = set()
        for term in self.anf(node):
            source_term = 0
            remaining = term
            while remaining:
                bit = remaining & -remaining
                word, lane = self.refs[bit.bit_length() - 1]
                source_term |= 1 << (word * 32 + lane)
                remaining ^= bit
            translated.add(source_term)
        return frozenset(translated)


def _literal(node: ast.expr) -> int:
    if not isinstance(node, ast.Constant) or type(node.value) is not int or node.value < 0:
        raise ValueError(f"nonconstant index, shift, or multiplier at line {node.lineno}")
    return node.value


def _shift(word: Word, amount: int, left: bool) -> Word:
    return tuple(word[index] if 0 <= (index := (bit - amount if left else bit + amount)) < 32 else 0 for bit in range(32))


def output_polynomials(output_word: int, root: Path = REPOSITORY_ROOT) -> tuple[Polynomial, ...]:
    """Exact source-bit ANFs for all 32 bits of one generated output word."""
    if not 0 <= output_word < 12:
        raise ValueError("Monolith5 has twelve output words")
    trace = trace_monolith(5, output_word, root=root)
    paths = {assignment["path"] for assignment in trace["assignments"]}
    if len(paths) != 1 or any(not ref.startswith("source[") for ref in trace["inputs"]):
        raise ValueError("Monolith5 output must have one source-only slice")
    refs = sorted(set().union(*trace_output_bits(5, output_word, root=root)), key=lambda ref: (ref[1], ref[0]))
    bdd = BDD(refs)
    wanted = {(assignment["line"], assignment["target"]) for assignment in trace["assignments"]}
    path = root / next(iter(paths))
    module = ast.parse(path.read_text(encoding="utf-8"))
    execute = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
    values: dict[str, Word] = {}
    output: Word | None = None
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
        if (statement.lineno, name) not in wanted:
            continue
        value = bdd.expression(statement.value, values)
        values[name] = value
        if name == f"dst_dwords[{output_word}]":
            output = value
    if output is None:
        raise ValueError(f"missing output word {output_word}")
    return tuple(bdd.source_polynomial(node) for node in output)


def _source_lane(source_id: int) -> tuple[int, int, int]:
    word, bit = divmod(source_id, 32)
    return (word % 18 // 3, bit, word // 18 * 3 + word % 3)


def _term_lanes(term: int) -> set[tuple[int, int]]:
    lanes: set[tuple[int, int]] = set()
    while term:
        bit = term & -term
        chunk, lane, _ = _source_lane(bit.bit_length() - 1)
        lanes.add((chunk, lane))
        term ^= bit
    return lanes


def _normalized_function(polynomial: Polynomial) -> tuple[tuple[int, int], frozenset[int]]:
    lanes = {_source_lane(source_id)[:2] for term in polynomial for source_id in _term_source_ids(term)}
    if len(lanes) != 1 or 0 in polynomial:
        raise ValueError("expected one nonconstant nine-input lane function")
    chunk, bit = next(iter(lanes))
    terms = frozenset(sum(1 << _source_lane(source_id)[2] for source_id in _term_source_ids(term)) for term in polynomial)
    return (chunk, bit), terms


def _term_source_ids(term: int) -> list[int]:
    result: list[int] = []
    while term:
        bit = term & -term
        result.append(bit.bit_length() - 1)
        term ^= bit
    return result


def _multiply(left: Polynomial, right: Polynomial) -> Polynomial:
    result: set[int] = set()
    for a in left:
        for b in right:
            term = a | b
            if term in result:
                result.remove(term)
            else:
                result.add(term)
    return frozenset(result)


def _factor(second: Polynomial, components: list[Polynomial]) -> tuple[int, Polynomial]:
    """Express second bit as a degree-2 polynomial in first-bit lanes."""
    basis: list[Polynomial] = []
    for subset in range(1 << len(components)):
        product: Polynomial = frozenset({0})
        for index, component in enumerate(components):
            if subset & (1 << index):
                product = _multiply(product, component)
        basis.append(product)
    reduced: dict[int, Polynomial] = {}
    combinations: dict[int, int] = {}
    for index, vector in enumerate(basis):
        combination = 1 << index
        while vector:
            pivot = max(vector)
            if pivot not in reduced:
                reduced[pivot] = vector
                combinations[pivot] = combination
                break
            vector ^= reduced[pivot]
            combination ^= combinations[pivot]
    residual = second
    solution = 0
    while residual:
        pivot = max(residual)
        if pivot not in reduced:
            break
        residual ^= reduced[pivot]
        solution ^= combinations[pivot]
    if solution & (1 << ((1 << len(components)) - 1)) and len(components) == 3:
        raise ValueError("unexpected cubic combination")
    reconstructed = residual
    for index, product in enumerate(basis):
        if solution & (1 << index):
            reconstructed ^= product
    if reconstructed != second:
        raise ValueError("quadratic factorization did not reconstruct the output bit")
    return solution, residual


def _truth_table(anf: frozenset[int]) -> str:
    truth = 0
    for assignment in range(512):
        if sum(1 for term in anf if assignment & term == term) & 1:
            truth |= 1 << assignment
    return f"{truth:0128x}"


def recover_model(root: Path = REPOSITORY_ROOT) -> Model:
    """Derive the complete two-stream formula from generated Monolith5."""
    outputs = [output_polynomials(word, root=root) for word in range(12)]
    functions: list[frozenset[int]] = []
    function_ids: dict[frozenset[int], int] = {}

    def function_id(anf: frozenset[int]) -> int:
        if anf not in function_ids:
            function_ids[anf] = len(functions)
            functions.append(anf)
        return function_ids[anf]

    entries: list[Entry] = []
    for position in range(168):
        word, offset = divmod(position, 28)
        first = outputs[word][offset + 2]
        constant = int(0 in first)
        grouped: dict[tuple[int, int], set[int]] = {}
        for term in first:
            if term == 0:
                continue
            lanes = _term_lanes(term)
            if len(lanes) != 1:
                raise ValueError(f"first output bit {position} mixes source lanes")
            grouped.setdefault(next(iter(lanes)), set()).add(term)
        if not 1 <= len(grouped) <= 3:
            raise ValueError(f"unexpected component count at bit {position}")
        components: list[Component] = []
        component_polys: list[Polynomial] = []
        for lane in sorted(grouped):
            polynomial = frozenset(grouped[lane])
            normalized_lane, normalized = _normalized_function(polynomial)
            assert normalized_lane == lane
            components.append((lane[0], lane[1], function_id(normalized)))
            component_polys.append(polynomial)
        reconstructed_first: Polynomial = frozenset({0}) if constant else frozenset()
        for polynomial in component_polys:
            reconstructed_first ^= polynomial
        if reconstructed_first != first:
            raise ValueError(f"lane decomposition did not reconstruct first output bit {position}")

        second_mask = 0
        residual_component: Component | None = None
        if position < 167:
            second_position = position + 1
            second_word, second_offset = divmod(second_position, 28)
            second = outputs[second_word + 6][second_offset + 2]
            second_mask, residual = _factor(second, component_polys)
            if residual:
                if position != 0:
                    raise ValueError(f"unexpected residual at second output bit {second_position}")
                lane, normalized = _normalized_function(residual)
                residual_component = (lane[0], lane[1], function_id(normalized))
        entries.append((constant, components, second_mask, residual_component))

    if len(functions) != 32:
        raise ValueError(f"expected 32 distinct nine-input functions, got {len(functions)}")
    if outputs[6][2] or any(outputs[word][bit] for word in range(12) for bit in (0, 1, 30, 31)):
        raise ValueError("fixed output bits are not zero")
    return {"version": 1, "luts": [_truth_table(function) for function in functions], "entries": entries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the recovered model as JSON")
    parser.add_argument("--verify", type=Path, help="compare a saved model with the generated source")
    args = parser.parse_args()
    model = recover_model()
    if args.verify is not None:
        saved = json.loads(args.verify.read_text(encoding="utf-8"))
        if saved != json.loads(json.dumps(model)):
            raise SystemExit("Monolith5 model differs from generated source")
        print("Monolith5 model exactly matches the generated source")
    elif args.json:
        print(json.dumps(model, separators=(",", ":")))
    else:
        print(f"Recovered {len(model['luts'])} nine-input functions and {len(model['entries'])} output positions")


if __name__ == "__main__":
    main()
