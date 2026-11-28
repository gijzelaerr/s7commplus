"""Order-number (MLFB) to device-name mapping."""

from __future__ import annotations

import pytest

from s7commplus.devices import DEVICE_NAMES, device_family, device_name


class TestDeviceName:
    def test_known_order_numbers(self) -> None:
        # The exact controllers from the open issues.
        assert device_name("6ES7 512-1DK01-0AB0") == "CPU 1512SP-1 PN"  # issue #12
        assert device_name("6ES7 215-1AG40-0XB0") == "CPU 1215C DC/DC/DC"  # issues #44/#70
        assert device_name("6ES7 212-1AE40-0XB0") == "CPU 1212C DC/DC/DC"  # issue #10
        assert device_name("6ES7 515-2AM00-0AB0") == "CPU 1515-2 PN"  # issue #34 family
        assert device_name("6ES7 841-0CC05-0YA5") == "CPU 841 (PLCSIM)"
        assert device_name("6ES7 512-1SM03-0AB0") == "CPU 1512SP F-1 PN"  # FW V4.1, reported by a live PLC

    def test_accepts_a_full_paom_string(self) -> None:
        # The middle field of a ServerSessionVersion PAOM string resolves.
        assert device_name("1;6ES7 215-1AG40-0XB0;V4.2") == "CPU 1215C DC/DC/DC"
        assert device_name("1;6ES7 215-1AG40-0XB0 ;V4.2") == "CPU 1215C DC/DC/DC"

    def test_whitespace_is_tolerated(self) -> None:
        assert device_name("  6ES7 215-1AG40-0XB0  ") == "CPU 1215C DC/DC/DC"

    def test_unknown_returns_none(self) -> None:
        assert device_name("6ES7 999-9ZZ99-0AB0") is None
        assert device_name("") is None
        assert device_name("garbage") is None

    def test_table_shape(self) -> None:
        assert len(DEVICE_NAMES) >= 100
        # Order numbers follow the 6ES7/6AG1 MLFB shape; every entry maps to a name.
        for order_number, name in DEVICE_NAMES.items():
            assert order_number.startswith(("6ES7", "6AG1")), order_number
            assert " " not in name or "CPU" in name or "SIPLUS" in name, name


class TestDeviceFamily:
    @pytest.mark.parametrize(
        ("order_number", "expected"),
        [
            ("6ES7 215-1AG40-0XB0", "s7-1200"),
            ("6ES7 212-1AE40-0XB0", "s7-1200"),
            ("6ES7 511-1AK00-0AB0", "s7-1500"),
            ("6ES7 515-2AM00-0AB0", "s7-1500"),
            ("6ES7 512-1DK01-0AB0", "s7-1500-sp"),
            ("6ES7 512-1SM03-0AB0", "s7-1500-sp"),
            ("6ES7 672-7AC00-0YA0", "s7-1500-sp"),
            ("6ES7 841-0CC05-0YA5", "plcsim"),
            ("6ES7 SIM-01500-VPLC", "plcsim"),
        ],
    )
    def test_classification(self, order_number: str, expected: str) -> None:
        assert device_family(order_number) == expected

    def test_unknown_returns_none(self) -> None:
        assert device_family("garbage") is None

    def test_every_table_entry_classifies(self) -> None:
        # The table is trimmed to S7-1200/1500-class controllers, so every
        # entry must classify into one of the supported families.
        families = set()
        for order_number in DEVICE_NAMES:
            family = device_family(order_number)
            assert family is not None, f"{order_number} does not classify"
            families.add(family)
        assert families <= {"s7-1200", "s7-1500", "s7-1500-sp", "plcsim", "et200"}


class TestErrorSourceConstants:
    def test_values(self) -> None:
        from s7commplus.protocol import ErrorSource

        assert ErrorSource.OBJECT_MANAGEMENT_SYSTEM == 0
        assert ErrorSource.OPERATING_STATE_CONTROL == 1
        assert ErrorSource.LOAD_MEMORY_CONTROL == 3
        assert ErrorSource.WORKING_MEMORY_CONTROL == 4
        assert ErrorSource.ALARMING_SYSTEM == 8
        assert ErrorSource.COMMUNICATION_SYSTEM == 33
        assert ErrorSource.EXECUTION_LEVEL_SYSTEM == 64

    def test_members_are_unique(self) -> None:
        from s7commplus.protocol import ErrorSource

        values = [int(member) for member in ErrorSource]
        assert len(values) == len(set(values))
