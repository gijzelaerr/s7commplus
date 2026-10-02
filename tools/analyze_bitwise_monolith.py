"""Exhaustively analyze a bitwise-only generated Monolith output word.

Run with ``python -m tools.analyze_bitwise_monolith 11 0``. The analysis is
read-only and refuses shifts, arithmetic, calls, and oversized input spaces.
Each output bit is represented by its complete Boolean truth table over the
same-position bits of the source words in its backward slice.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from tools.trace_v1_session_key_output import REPOSITORY_ROOT, trace_monolith


@dataclass(frozen=True)
class BitStatistics:
    bit: int
    essential_source_words: tuple[int, ...]
    ones: int
    anf_degree: int
    anf_terms: int
    truth_sha256: str


@dataclass(frozen=True)
class BitwiseAnalysis:
    monolith: int
    output_word: int
    source_words: tuple[int, ...]
    assignment_count: int
    truth_tables: tuple[int, ...]
    bits: tuple[BitStatistics, ...]

    def evaluate(self, source_words: Mapping[int, int]) -> int:
        """Evaluate the recovered output word for one concrete source vector."""
        output = 0
        for bit, truth in enumerate(self.truth_tables):
            row = sum(((source_words[word] >> bit) & 1) << index for index, word in enumerate(self.source_words))
            output |= ((truth >> row) & 1) << bit
        return output


def _variable_masks(count: int) -> tuple[int, ...]:
    """Truth-table masks for source-bit variables in row-index order."""
    rows = 1 << count
    masks: list[int] = []
    for variable in range(count):
        half = 1 << variable
        mask = ((1 << half) - 1) << half
        width = half * 2
        while width < rows:
            mask |= mask << width
            width *= 2
        masks.append(mask)
    return tuple(masks)


def _degree_masks(count: int) -> tuple[int, ...]:
    """Masks for monomials of each degree in algebraic normal form."""
    masks = [1]
    rows = 1
    for _ in range(count):
        next_masks = [0] * (len(masks) + 1)
        for degree, mask in enumerate(masks):
            next_masks[degree] |= mask
            next_masks[degree + 1] |= mask << rows
        masks = next_masks
        rows *= 2
    return tuple(masks)


def _anf_coefficients(truth: int, variable_masks: tuple[int, ...]) -> int:
    """Apply the Boolean Möbius transform using truth-table bitsets."""
    coefficients = truth
    for variable, high_half in enumerate(variable_masks):
        coefficients ^= (coefficients << (1 << variable)) & high_half
    return coefficients


def anf_monomial_masks(analysis: BitwiseAnalysis) -> dict[tuple[int, ...], int]:
    """Return exact 32-bit coefficients for each input-word monomial.

    The keys are sorted source-word tuples: ``()`` is the constant term,
    ``(a,)`` a linear term, and ``(a, b)`` an AND term. Coefficient bits select
    which output-bit lanes contain the term.
    """
    variable_masks = _variable_masks(len(analysis.source_words))
    coefficients_by_monomial: dict[tuple[int, ...], int] = {}
    for bit, truth in enumerate(analysis.truth_tables):
        coefficients = _anf_coefficients(truth, variable_masks)
        while coefficients:
            lowest = coefficients & -coefficients
            subset = lowest.bit_length() - 1
            words = tuple(word for variable, word in enumerate(analysis.source_words) if subset & (1 << variable))
            coefficients_by_monomial[words] = coefficients_by_monomial.get(words, 0) | (1 << bit)
            coefficients ^= lowest
    return dict(sorted(coefficients_by_monomial.items()))


def _word_index(node: ast.Subscript, array: str) -> int:
    if not isinstance(node.value, ast.Name) or node.value.id != array:
        raise ValueError(f"expected {array} word at line {node.lineno}")
    if not isinstance(node.slice, ast.Constant) or type(node.slice.value) is not int or node.slice.value < 0:
        raise ValueError(f"dynamic {array} index at line {node.lineno}")
    return node.slice.value


def _target_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name) and node.id.startswith("uVar"):
        return node.id
    if isinstance(node, ast.Subscript):
        return f"dst_dwords[{_word_index(node, 'dst_dwords')}]"
    raise ValueError(f"unsupported assignment target at line {node.lineno}")


def _evaluate_bitwise(
    node: ast.expr,
    bit: int,
    universe: int,
    inputs: Mapping[int, int],
    values: Mapping[str, int],
) -> int:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return universe if (node.value >> bit) & 1 else 0
    if isinstance(node, ast.Name):
        if node.id == "_U32":
            return universe
        if node.id not in values:
            raise ValueError(f"unassigned scalar {node.id} at line {node.lineno}")
        return values[node.id]
    if isinstance(node, ast.Subscript):
        index = _word_index(node, "src_dwords")
        if index not in inputs:
            raise ValueError(f"unmapped source word {index} at line {node.lineno}")
        return inputs[index]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        return universe ^ _evaluate_bitwise(node.operand, bit, universe, inputs, values)
    if isinstance(node, ast.BinOp):
        left = _evaluate_bitwise(node.left, bit, universe, inputs, values)
        right = _evaluate_bitwise(node.right, bit, universe, inputs, values)
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
    raise ValueError(f"non-bitwise expression {type(node).__name__} at line {node.lineno}")


def analyze_bitwise_output(
    monolith: int,
    output_word: int,
    root: Path = REPOSITORY_ROOT,
    max_inputs: int = 20,
) -> BitwiseAnalysis:
    """Analyze one output across all 2^N source-bit combinations per bit.

    Only a single-file, bitwise-only backward slice is accepted. This makes
    each 32-bit output lane independent, so the truth tables are exhaustive.
    """
    trace = trace_monolith(monolith, output_word, root=root)
    paths = {item["path"] for item in trace["assignments"]}
    if len(paths) != 1:
        raise ValueError("multi-file slices are not supported by the bitwise analyzer")
    if any(not item.startswith("source[") for item in trace["inputs"]):
        raise ValueError("slice has non-source inputs")
    source_words = tuple(int(item.removeprefix("source[").removesuffix("]")) for item in trace["inputs"])
    if len(source_words) > max_inputs:
        raise ValueError(f"{len(source_words)} source words exceed the {max_inputs}-input truth-table limit")

    path = next(iter(paths))
    module = ast.parse((root / path).read_text(encoding="utf-8"))
    execute = next(item for item in module.body if isinstance(item, ast.FunctionDef) and item.name == "execute")
    wanted = {(item["line"], item["target"]) for item in trace["assignments"]}
    statements: list[tuple[str, ast.expr]] = []
    for statement in execute.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        try:
            target = _target_name(statement.targets[0])
        except ValueError:
            continue  # Input buffer setup or final destination copy.
        if (statement.lineno, target) in wanted:
            statements.append((target, statement.value))
    if len(statements) != len(wanted):
        raise ValueError("backward slice does not match generated assignments")

    variable_masks = _variable_masks(len(source_words))
    rows = 1 << len(source_words)
    universe = (1 << rows) - 1
    degree_masks = _degree_masks(len(source_words))
    tables: list[int] = []
    statistics: list[BitStatistics] = []
    for bit in range(32):
        inputs = dict(zip(source_words, variable_masks))
        values: dict[str, int] = {}
        for target, expression in statements:
            values[target] = _evaluate_bitwise(expression, bit, universe, inputs, values)
        truth = values[f"dst_dwords[{output_word}]"]
        tables.append(truth)
        essential = tuple(
            word
            for variable, word in enumerate(source_words)
            if ((truth ^ (truth >> (1 << variable))) & (universe ^ variable_masks[variable])) != 0
        )
        coefficients = _anf_coefficients(truth, variable_masks)
        degree = max(degree for degree, mask in enumerate(degree_masks) if coefficients & mask) if coefficients else -1
        statistics.append(
            BitStatistics(
                bit=bit,
                essential_source_words=essential,
                ones=truth.bit_count(),
                anf_degree=degree,
                anf_terms=coefficients.bit_count(),
                truth_sha256=hashlib.sha256(truth.to_bytes((rows + 7) // 8, "little")).hexdigest(),
            )
        )
    return BitwiseAnalysis(monolith, output_word, source_words, len(statements), tuple(tables), tuple(statistics))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monolith", type=int, choices=range(1, 12))
    parser.add_argument("output_word", type=int)
    parser.add_argument("--json", action="store_true", help="emit per-bit statistics and truth-table hashes")
    args = parser.parse_args(argv)
    try:
        analysis = analyze_bitwise_output(args.monolith, args.output_word)
    except (OSError, ValueError, StopIteration) as exc:
        parser.error(str(exc))
    if args.json:
        print(
            json.dumps(
                {
                    "monolith": analysis.monolith,
                    "output_word": analysis.output_word,
                    "source_words": analysis.source_words,
                    "assignments": analysis.assignment_count,
                    "bits": [asdict(item) for item in analysis.bits],
                    "anf_monomials": [
                        {"source_words": words, "output_mask": f"0x{mask:08X}"}
                        for words, mask in anf_monomial_masks(analysis).items()
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"Monolith{analysis.monolith} output word {analysis.output_word}: {analysis.assignment_count} assignments")
        print(f"Source words: {list(analysis.source_words)}")
        print(f"ANF monomials: {len(anf_monomial_masks(analysis))}")
        for item in analysis.bits:
            print(
                f"bit {item.bit:2}: essential={len(item.essential_source_words):2} "
                f"ones={item.ones:6} ANF degree={item.anf_degree:2} terms={item.anf_terms:6} "
                f"sha256={item.truth_sha256[:12]}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
