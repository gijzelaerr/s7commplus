"""Tests for conservative, versioned SessionKey output-word tracing."""

import pytest

from tools.trace_v1_session_key_output import DependencyGraph, format_input_ranges, trace_monolith


pytestmark = pytest.mark.analysis  # studies retired HarpoS7 code in old/; pass --analysis


def test_input_ranges_are_compact_and_keep_input_kinds_separate() -> None:
    assert format_input_ranges(["source[0]", "source[1]", "source[3]", "scratch_initial[2]"]) == (
        "source[0-1], source[3], scratch_initial[2]"
    )
    assert format_input_ranges([]) == "(constant only)"


def test_overwritten_scalar_does_not_create_false_dependency() -> None:
    graph = DependencyGraph()
    graph.add_execute(
        "example.py",
        """
def execute(source, destination):
    src_dwords = _to_uints(source)
    dst_dwords = _to_uints(destination)
    uVar1 = src_dwords[0]
    uVar1 = src_dwords[1]
    dst_dwords[0] = uVar1
    destination[:] = _from_uints(dst_dwords)
""",
    )
    result = graph.trace(0)
    assert result["inputs"] == ["source[1]"]
    assert [item["line"] for item in result["assignments"]] == [6, 7]


def test_self_assignment_uses_previous_version() -> None:
    graph = DependencyGraph()
    graph.add_execute(
        "example.py",
        """
def execute(source, destination):
    uVar1 = src_dwords[0]
    uVar1 = uVar1 ^ src_dwords[1]
    dst_dwords[0] = uVar1
""",
    )
    assert graph.trace(0)["inputs"] == ["source[0]", "source[1]"]


def test_shared_scratch_overwrite_across_parts() -> None:
    graph = DependencyGraph()
    graph.add_execute("part1.py", "def execute(source, locals_):\n    locals_[4] = src_dwords[0]\n")
    graph.add_execute("part2.py", "def execute(source, locals_):\n    locals_[4] = src_dwords[1]\n")
    graph.add_execute("part3.py", "def execute(destination, locals_):\n    dst_dwords[0] = locals_[4]\n")
    result = graph.trace(0)
    assert result["inputs"] == ["source[1]"]
    assert [item["path"] for item in result["assignments"]] == ["part2.py", "part3.py"]


def test_original_destination_and_unset_scratch_are_explicit_inputs() -> None:
    graph = DependencyGraph()
    graph.add_execute(
        "example.py",
        "def execute(destination, locals_):\n    dst_dwords[0] = dst_dwords[0] ^ locals_[3]\n",
    )
    assert graph.trace(0)["inputs"] == ["destination_before[0]", "scratch_initial[3]"]


def test_unsupported_constructs_fail_instead_of_disappearing() -> None:
    graph = DependencyGraph()
    with pytest.raises(ValueError, match="dynamic word index"):
        graph.add_execute("bad.py", "def execute(source, index):\n    dst_dwords[0] = src_dwords[index]\n")
    with pytest.raises(ValueError, match="unsupported statement"):
        graph.add_execute("bad.py", "def execute(source):\n    if source:\n        pass\n")
    with pytest.raises(ValueError, match="no write to dst_dwords"):
        DependencyGraph().trace(0)


@pytest.mark.parametrize("monolith", range(1, 12))
def test_checked_in_monolith_output_has_closed_trace(monolith: int) -> None:
    result = trace_monolith(monolith, 0)
    assert result["assignments"]
    assert result["inputs"]
    assert all(str(item).startswith("source[") for item in result["inputs"])
    assert result["assignments"][-1]["target"] == "dst_dwords[0]"
    if monolith in (9, 10):
        assert len({item["path"] for item in result["assignments"]}) > 1
