"""Tests for the read-only generated-transform source map."""

import pytest

from tools.map_v1_session_key_monoliths import map_artifacts, map_execute


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis


def test_map_execute_distinguishes_word_reads_and_writes() -> None:
    source = """
def execute(source, destination, locals_):
    src_dwords = _to_uints(source)
    dst_dwords = _to_uints(destination)
    locals_[4] = src_dwords[0xA] ^ dst_dwords[2]
    dst_dwords[3] = locals_[4] ^ src_dwords[0]
"""
    assert map_execute(source) == {
        "src_dwords": {"read": [0, 10], "write": []},
        "dst_dwords": {"read": [2], "write": [3]},
        "locals_": {"read": [4], "write": [4]},
    }


def test_map_execute_rejects_dynamic_index() -> None:
    with pytest.raises(ValueError, match="dynamic src_dwords index"):
        map_execute("def execute(source, index):\n    return src_dwords[index]\n")


def test_checked_in_generated_sources_have_mappable_accesses() -> None:
    records = map_artifacts()
    assert len(records) >= 20
    monolith1 = next(record for record in records if str(record["path"]).endswith("/monolith1.py"))
    accesses = monolith1["word_accesses"]
    assert accesses["src_dwords"]["read"] == list(range(18))
    assert accesses["dst_dwords"]["write"] == list(range(18))
