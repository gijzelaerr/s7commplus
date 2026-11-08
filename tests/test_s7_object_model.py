"""Attribute tables for the object classes this package works with."""

from __future__ import annotations

import pytest

from s7commplus.object_model import (
    ATTRIBUTE_NAMES,
    CLASS_NAMES,
    attribute_name,
    describe_attribute,
)
from s7commplus.protocol import Ids, ObjectId


class TestTables:
    def test_class_names(self) -> None:
        assert CLASS_NAMES[287] == "ServerSession"
        assert CLASS_NAMES[2520] == "PLCProgram"
        assert CLASS_NAMES[0x9EA] == "Block"
        assert CLASS_NAMES[0x883] == "CPUexecUnit"

    def test_block_attributes(self) -> None:
        assert attribute_name(0x9EA, 0x9D9) == "BlockNumber"
        assert attribute_name(0x9EA, 0x9DA) == "AutoNumbering"
        assert attribute_name(0x9EA, 0x9DB) == "BlockLanguage"
        assert attribute_name(0x9EA, 0x9DC) == "KnowhowProtected"
        assert attribute_name(0x9EA, 0x9DF) == "Unlinked"

    def test_cpu_exec_unit_attributes(self) -> None:
        assert attribute_name(0x883, 0x877) == "OperatingStateREQ"
        assert attribute_name(0x883, 0xD9E) == "OperatingState"

    def test_server_session_attributes(self) -> None:
        assert attribute_name(287, 299) == "Role"
        assert attribute_name(287, 305) == "Roles"
        assert attribute_name(287, 306) == "Version"

    def test_unknown_pair_is_none(self) -> None:
        assert attribute_name(2574, 99999) is None
        assert attribute_name(99999, 233) is None


class TestDescribe:
    def test_known_renders_class_dot_name(self) -> None:
        assert describe_attribute(0x9EA, 0x9DB) == "Block.BlockLanguage"
        assert describe_attribute(0x883, 0xD9E) == "CPUexecUnit.OperatingState"

    def test_unknown_attribute_renders_numerically(self) -> None:
        assert describe_attribute(287, 99999) == "ServerSession attribute 99999"

    def test_unknown_class_renders_numerically(self) -> None:
        assert describe_attribute(4711, 233) == "class 4711 attribute 233"


class TestNoDriftAgainstProtocol:
    """The tables must agree with the constants the code already uses.

    These pins exist so a future edit to protocol.py cannot silently
    desynchronize the two.
    """

    @pytest.mark.parametrize(
        ("class_id", "attribute_id", "constant"),
        [
            (287, 300, ObjectId.SERVER_SESSION_CLIENT_RID),
            (287, 306, ObjectId.SERVER_SESSION_VERSION),
            (1001, Ids.SUBSCRIPTION_CREDIT_LIMIT, Ids.SUBSCRIPTION_CREDIT_LIMIT),
            (1001, Ids.SUBSCRIPTION_CYCLE_TIME, Ids.SUBSCRIPTION_CYCLE_TIME),
            (1001, Ids.SUBSCRIPTION_ACTIVE, Ids.SUBSCRIPTION_ACTIVE),
        ],
    )
    def test_table_matches_constants(self, class_id: int, attribute_id: int, constant: int) -> None:
        assert attribute_id == constant
        assert (class_id, attribute_id) in ATTRIBUTE_NAMES

    def test_cpu_state_attributes_match(self) -> None:
        # The corroborating attributes get_cpu_state() reads.
        assert attribute_name(0x883, Ids.CPU_EXEC_UNIT_EXECUTING) == "AlarmOBsLoad_LastPC"
        assert attribute_name(0x883, Ids.CPU_EXEC_UNIT_OPERATING_MODE) == "ProgramCycleLoadActual"

    def test_no_duplicate_names_within_a_class(self) -> None:
        per_class: dict[int, set[str]] = {}
        for (_class_id, _attr_id), name in ATTRIBUTE_NAMES.items():
            per_class.setdefault(_class_id, set())
            assert name not in per_class[_class_id], f"duplicate attribute name {name!r}"
            per_class[_class_id].add(name)


class TestClassCoverage:
    def test_every_attribute_class_has_a_name(self) -> None:
        # describe_attribute() must never render "class N" for a class that
        # has attributes in the table.
        missing = {class_id for class_id, _attribute_id in ATTRIBUTE_NAMES} - set(CLASS_NAMES)
        assert not missing, f"classes with attributes but no CLASS_NAMES entry: {sorted(missing)}"

    def test_data_block_is_documented_as_absent(self) -> None:
        # DataBlock's attributes are its per-tag tree, not fixed ids; the
        # class stays out of the table on purpose.
        assert 2574 not in CLASS_NAMES
        assert not [key for key in ATTRIBUTE_NAMES if key[0] == 2574]

    def test_server_session_renders_by_name(self) -> None:
        assert describe_attribute(287, 299) == "ServerSession.Role"
