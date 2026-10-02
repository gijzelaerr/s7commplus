"""Runtime-migration checks for Monolith5.

`family0/monolith5_compact.execute` replaced `_generated/monolith5.execute`
as the function ``monolith_wrappers.py`` actually calls. These tests prove
the byte-level entry point matches the generated code on the upstream
fixture and on random vectors (including that destination bytes beyond the
12 written words are left untouched), guard against a regression back to
importing the generated module at runtime, and guard against
`monolith5_compact.py` drifting out of sync with the generator that produces
it from `tools/monolith5_gate_model.json` and `tools/monolith5_model.json`.
"""

from __future__ import annotations

import random
from pathlib import Path

from tools.compile_monolith5 import compile_source

from old.family0 import monolith5_compact, monolith_wrappers
from old.family0._generated import monolith5 as generated_monolith5
import pytest


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_FIXTURES = Path(__file__).parent / "fixtures/family0/monoliths"


def test_compact_module_matches_generator_output() -> None:
    """Guards against hand-edits or a stale checked-in file after a model change."""
    compact_path = Path(monolith5_compact.__file__)
    assert compact_path.read_text(encoding="utf-8") == compile_source()


def test_compact_execute_matches_upstream_fixture() -> None:
    source = (_FIXTURES / "monolith5-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith5-dst.bin").read_bytes()

    destination = bytearray(len(expected))
    monolith5_compact.execute(destination, source)

    assert bytes(destination) == expected


def test_compact_execute_matches_generated_on_random_vectors_and_preserves_tail() -> None:
    rng = random.Random(0xC0FFEE05)
    for _ in range(200):
        source = bytes(rng.getrandbits(8) for _ in range(216))
        # A destination longer than 48 bytes exercises that both
        # implementations leave the tail untouched.
        tail = bytes(rng.getrandbits(8) for _ in range(20))

        generated_destination = bytearray(48) + bytearray(tail)
        generated_monolith5.execute(generated_destination, source)

        compact_destination = bytearray(48) + bytearray(tail)
        monolith5_compact.execute(compact_destination, source)

        assert bytes(compact_destination) == bytes(generated_destination)
        assert bytes(compact_destination[48:]) == tail


def test_monolith_wrappers_no_longer_imports_generated_monolith5() -> None:
    assert not hasattr(monolith_wrappers, "monolith5")
    assert monolith_wrappers.monolith5_compact is monolith5_compact
