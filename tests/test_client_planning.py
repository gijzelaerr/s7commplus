"""The request planning both clients share for named writes and split subscriptions (#168)."""

from __future__ import annotations

import dataclasses

import pytest

from s7commplus.catalog import SymbolicTag
from s7commplus.client import _plan_subscription_groups, _plan_tag_writes
from s7commplus.protocol import DataType
from s7commplus.subscription import SubscriptionItem
from s7commplus.typeinfo import Softdatatype


def _tag(name: str, lid: int, datatype: DataType | None = DataType.INT) -> SymbolicTag:
    return SymbolicTag(name, 0x8A0E0001, (lid,), Softdatatype.INT, datatype)  # type: ignore[arg-type]


class TestPlanTagWrites:
    def test_one_item_per_tag_in_order(self) -> None:
        tags = [_tag("DB.a", 1), _tag("DB.b", 2)]
        items = _plan_tag_writes(tags, [b"\x00\x01", b"\x00\x02"])
        assert items == [
            (0x8A0E0001, [1], b"\x00\x01", 0, DataType.INT),
            (0x8A0E0001, [2], b"\x00\x02", 0, DataType.INT),
        ]

    def test_a_tag_without_a_wire_type_is_refused(self) -> None:
        with pytest.raises(ValueError, match="DB.b"):
            _plan_tag_writes([_tag("DB.a", 1), _tag("DB.b", 2, datatype=None)], [b"\x00\x01", b"\x00\x02"])


class TestPlanSubscriptionGroups:
    def test_empty_items_are_refused(self) -> None:
        with pytest.raises(ValueError, match="at least one item"):
            _plan_subscription_groups([], 0x70000F90, 100, 10, 0, 0)

    def test_reference_ids_stay_unique_across_groups(self) -> None:
        items = [SubscriptionItem.from_access_sequence(f"8A0E0001.{lid:X}") for lid in range(1, 61)]
        groups = _plan_subscription_groups(items, 0x70000F90, 100, 10, 960, 0)
        assert len(groups) > 1
        reference_ids = [item.reference_id for group in groups for item in group]
        assert reference_ids == list(range(1, 61))

    def test_duplicate_reference_ids_are_refused(self) -> None:
        item = dataclasses.replace(SubscriptionItem.from_access_sequence("8A0E0001.1"), reference_id=5)
        with pytest.raises(ValueError, match="duplicate"):
            _plan_subscription_groups([item, item], 0x70000F90, 100, 10, 0, 0)
