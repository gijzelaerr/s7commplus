"""Checks for the compact Monolith11 in ``old/family0``.

``monolith11_compact.execute`` replaced ``_generated/monolith11.execute`` for
decoding encoded values. These tests prove the byte-level entry point (not
just the word-level formula already covered in
``test_v1_session_key_bitwise_analysis.py``) is equivalent, and that the runtime
no longer needs either, because it passes decoded integers.
"""

from __future__ import annotations

import random
from pathlib import Path

import sys

import s7commplus.v1_session_key.handshake  # noqa: F401  (loads the whole runtime)
from old.family0 import encoding, monolith11_compact
from old.family0._generated import monolith11 as generated_monolith11
import pytest


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis

_FIXTURES = Path(__file__).parent / "fixtures/family0/monoliths"


def test_compact_execute_matches_upstream_fixture() -> None:
    source = (_FIXTURES / "monolith11-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith11-dst.bin").read_bytes()

    destination = bytearray(len(expected))
    monolith11_compact.execute(destination, source)

    assert bytes(destination) == expected


def test_compact_execute_matches_generated_on_random_vectors_and_preserves_tail() -> None:
    rng = random.Random(0xC0FFEE11)
    for _ in range(100):
        source = bytes(rng.getrandbits(8) for _ in range(120))
        # A destination longer than 20 bytes exercises that both
        # implementations leave the tail untouched.
        tail = bytes(rng.getrandbits(8) for _ in range(72))

        generated_destination = bytearray(20) + bytearray(tail)
        generated_monolith11.execute(generated_destination, source)

        compact_destination = bytearray(20) + bytearray(tail)
        monolith11_compact.execute(compact_destination, source)

        assert bytes(compact_destination) == bytes(generated_destination)
        assert bytes(compact_destination[20:]) == tail


def test_only_the_encoded_value_decoder_uses_monolith11() -> None:
    assert encoding.monolith11_compact is monolith11_compact
    runtime = [module for name, module in sys.modules.items() if name.startswith("s7commplus.v1_session_key")]
    assert runtime and not any("monolith" in name for module in runtime for name in vars(module))
