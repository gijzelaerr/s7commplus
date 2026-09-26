"""Correctness-gated setup-only benchmark; never a whole-authentication ratio."""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
from typing import Any

from tools.benchmark_session_auth_models import measure
from tools.recover_transform7_setup import capture_setup
from tools.transform7_setup_integer import LIMIT, model


def benchmark(
    samples: int = 7, iterations: int = 10, source_count: int = 8, warmups: int = 2, seed: int = 0xC5B
) -> dict[str, Any]:
    if samples <= 0 or iterations <= 0 or source_count <= 0 or warmups < 0:
        raise ValueError("expected positive sample/iteration/source counts and nonnegative warmups")
    rng = random.Random(seed)
    cases = [(0, 0, 0), (LIMIT - 1,) * 3]
    cases.extend(tuple(rng.getrandbits(160) for _ in range(3)) for _ in range(max(0, source_count - len(cases))))
    sources = [b"".join(value.to_bytes(20, "little") for value in case) for case in cases[:source_count]]

    def inputs(source: bytes) -> tuple[int, int, int]:
        values = [int.from_bytes(source[offset : offset + 20], "little") for offset in (0, 20, 40)]
        return values[0], values[1], values[2]

    def native(source: bytes) -> bytes:
        return b"".join(value.to_bytes(20, "little") for value in capture_setup(*inputs(source)))

    def compact(source: bytes) -> bytes:
        return b"".join(value.to_bytes(20, "little") for value in model(*inputs(source)).slots)

    if not all(native(source) == compact(source) for source in sources):
        raise AssertionError("input-only setup disagrees with generated runtime")
    generated = measure(native, sources, samples=samples, iterations=iterations, warmups=warmups)
    recovered = measure(compact, sources, samples=samples, iterations=iterations, warmups=warmups)
    return {
        "scope": "setup ONLY: 60 input bytes to 80 output bytes (four exact unsigned-160-bit representatives); native capture/dispatcher-patching overhead included; NOT whole Transform7 or authentication speedup",
        "configuration": {
            "samples": samples,
            "iterations": iterations,
            "source_count": source_count,
            "warmups": warmups,
            "seed": seed,
        },
        "environment": {"python": sys.version, "platform": platform.platform()},
        "generated_setup_capture": generated,
        "input_only_model": recovered,
        "capture_over_model_ratio": generated["median_us"] / recovered["median_us"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--source-count", type=int, default=8)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0xC5B)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.samples, args.iterations, args.source_count, args.warmups, args.seed), indent=2))


if __name__ == "__main__":
    main()
