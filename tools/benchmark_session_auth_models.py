"""Reproducible correctness-first microbenchmarks for recovered models.

Run with ``python -m tools.benchmark_session_auth_models``. Partial Monolith7
models report their own cost and deliberately receive no full-transform ratio.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import platform
import random
import statistics
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Implementation:
    """A byte-interface adapter and the output words it promises to recover."""

    name: str
    module: str
    monolith: int
    source_words: int
    output_words: tuple[int, ...]
    generated: bool = False

    @property
    def complete(self) -> bool:
        return self.output_words == tuple(range({5: 12, 7: 36, 11: 5}[self.monolith]))

    def adapter(self) -> Callable[[bytes], bytes]:
        module = importlib.import_module(self.module)
        if self.generated:

            def execute(source: bytes) -> bytes:
                destination = bytearray(4 * len(self.output_words))
                module.execute(destination, source)
                return bytes(destination)

        else:

            def execute(source: bytes) -> bytes:
                words = module.execute_words(struct.unpack(f"<{self.source_words}I", source))
                return struct.pack(f"<{len(self.output_words)}I", *words)

        return execute


def implementations() -> list[Implementation]:
    """Include optional recovered models only when their modules exist."""
    cases = [
        Implementation(
            f"monolith{number}_generated",
            f"s7commplus.session_auth.family0._generated.monolith{number}",
            number,
            source_words,
            tuple(range(output_words)),
            True,
        )
        for number, source_words, output_words in [(5, 54, 12), (7, 24, 36), (11, 30, 5)]
    ]
    cases.extend(
        [
            Implementation("monolith5_lut", "tools.monolith5_model", 5, 54, tuple(range(12))),
            Implementation("monolith5_gates", "tools.monolith5_gate_model", 5, 54, tuple(range(12))),
            Implementation("monolith7_middle", "tools.monolith7_middle_model", 7, 24, (3, 4, 5)),
            Implementation("monolith7_tail", "tools.monolith7_tail_model", 7, 24, (15, 16, 17)),
            Implementation("monolith7_full", "tools.monolith7_full_model", 7, 24, tuple(range(36))),
            Implementation("monolith11_formula", "tools.monolith11_model", 11, 30, tuple(range(5))),
        ]
    )
    return [case for case in cases if importlib.util.find_spec(case.module) is not None]


def validate(case: Implementation, execute: Callable[[bytes], bytes], sources: Sequence[bytes]) -> None:
    """Compare every promised word with fixture and generated outputs."""
    fixture_dir = _ROOT / "tests/fixtures/family0/monoliths"
    fixture_source = (fixture_dir / f"monolith{case.monolith}-src.bin").read_bytes()
    fixture_expected = (fixture_dir / f"monolith{case.monolith}-dst.bin").read_bytes()
    generated = importlib.import_module(f"s7commplus.session_auth.family0._generated.monolith{case.monolith}")
    for source, expected in [(fixture_source, fixture_expected), *((source, None) for source in sources)]:
        if expected is None:
            destination = bytearray({5: 48, 7: 144, 11: 20}[case.monolith])
            generated.execute(destination, source)
            expected = bytes(destination)
        selected = b"".join(expected[word * 4 : word * 4 + 4] for word in case.output_words)
        if execute(source) != selected:
            raise AssertionError(f"{case.name} disagrees with generated/fixture output")


def measure(
    execute: Callable[[bytes], bytes], sources: Sequence[bytes], *, samples: int, iterations: int, warmups: int
) -> dict[str, float]:
    """Measure per-call time; keep validation and imports outside the timer."""
    if samples < 1 or iterations < 1 or warmups < 0 or not sources:
        raise ValueError("samples, iterations and source count must be positive; warmups must be nonnegative")
    for _ in range(warmups):
        for source in sources:
            execute(source)
    timings = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            for source in sources:
                execute(source)
        timings.append((time.perf_counter_ns() - start) / (iterations * len(sources)) / 1000)
    median = statistics.median(timings)
    return {
        "median_us": median,
        "mad_us": statistics.median(abs(value - median) for value in timings),
        "min_us": min(timings),
        "max_us": max(timings),
    }


def import_cost(module: str, repeats: int) -> float | None:
    """Measure uncached module import in fresh interpreters, excluding startup."""
    if repeats == 0:
        return None
    script = "import importlib,time,sys; t=time.perf_counter_ns(); importlib.import_module(sys.argv[1]); print(time.perf_counter_ns()-t)"
    values = [
        int(subprocess.check_output([sys.executable, "-c", script, module], cwd=_ROOT, text=True)) / 1_000_000
        for _ in range(repeats)
    ]
    return statistics.median(values)


def benchmark(
    *,
    samples: int = 7,
    iterations: int = 10,
    source_count: int = 4,
    warmups: int = 2,
    import_repeats: int = 3,
    seed: int = 0x5E5510,
    names: Sequence[str] = (),
) -> dict[str, Any]:
    """Produce JSON-serializable measurements with explicit scope and ratios."""
    if source_count < 1 or import_repeats < 0:
        raise ValueError("source_count must be positive and import_repeats nonnegative")
    cases = implementations()
    unknown = set(names) - {case.name for case in cases}
    if unknown:
        raise ValueError(f"unknown or unavailable implementations: {sorted(unknown)}")
    if names:
        cases = [case for case in cases if case.name in names]
    sources = {
        number: [random.Random(seed + number + index).randbytes(words * 4) for index in range(source_count)]
        for number, words in [(5, 54), (7, 24), (11, 30)]
    }
    rows = []
    for case in cases:
        execute = case.adapter()
        validate(case, execute, sources[case.monolith])
        module_path = Path(importlib.import_module(case.module).__file__)
        data_path = module_path.with_suffix(".json")
        files = [module_path] + ([data_path] if data_path.exists() else [])
        if case.name == "monolith5_gates":
            files.append(module_path.with_name("monolith5_model.json"))
        rows.append(
            {
                "name": case.name,
                "module": case.module,
                "monolith": case.monolith,
                "complete": case.complete,
                "output_words": list(case.output_words),
                "artifact_bytes": sum(path.stat().st_size for path in files),
                "artifact_files": [str(path.relative_to(_ROOT)) for path in files],
                "cold_import_median_ms": import_cost(case.module, import_repeats),
                **measure(execute, sources[case.monolith], samples=samples, iterations=iterations, warmups=warmups),
            }
        )
    baselines = {row["monolith"]: row["median_us"] for row in rows if row["name"].endswith("_generated")}
    for row in rows:
        baseline = baselines.get(row["monolith"])
        row["generated_over_model_ratio"] = baseline / row["median_us"] if baseline is not None and row["complete"] else None
    return {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "configuration": {
            "samples": samples,
            "iterations": iterations,
            "source_count": source_count,
            "warmups": warmups,
            "import_repeats": import_repeats,
            "seed": seed,
        },
        "scope": "Single-thread byte-to-byte calls including source unpacking/output allocation and packing. "
        "Imports and correctness checks excluded from call timings. Partial outputs have no full-transform ratio. "
        "Artifact size includes module and direct model JSON data, not shared Python dependencies.",
        "results": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--source-count", type=int, default=4)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--import-repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0x5E5510)
    parser.add_argument("--implementations", nargs="*", default=[])
    args = parser.parse_args()
    print(
        json.dumps(
            benchmark(
                samples=args.samples,
                iterations=args.iterations,
                source_count=args.source_count,
                warmups=args.warmups,
                import_repeats=args.import_repeats,
                seed=args.seed,
                names=args.implementations,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
