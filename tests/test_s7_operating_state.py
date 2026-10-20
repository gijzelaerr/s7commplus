"""Operating-state attribute ids and request values (groundwork for #8)."""

from __future__ import annotations

import pytest

from s7commplus.connection import _build_set_operating_state_payload, _build_set_variable_payload
from s7commplus.protocol import (
    OPERATING_STATE_RUN_OBSERVED,
    OPERATING_STATE_STOP_OBSERVED,
    DataType,
    Ids,
    OperatingStateRequest,
)


class TestOperatingStateAttributes:
    def test_attribute_ids(self) -> None:
        # The writable request attribute and the read-only state attribute are
        # distinct attributes of the CPUexecUnit object (RID 52).
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ == 0x877
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE == 0xD9E
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE != Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ

    def test_executing_mode_attributes_unchanged(self) -> None:
        # The corroborating attributes get_cpu_state() already reads stay put.
        assert Ids.CPU_EXEC_UNIT_EXECUTING == 8064
        assert Ids.CPU_EXEC_UNIT_OPERATING_MODE == 8065


class TestOperatingStateRequestValues:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("STOP", 1),
            ("RESET_RETENTIVE", 2),
            ("RUN", 3),
            ("RUN_REDUNDANT", 4),
        ],
    )
    def test_request_values(self, name: str, value: int) -> None:
        assert OperatingStateRequest[name] == value

    def test_values_are_distinct(self) -> None:
        values = [int(member) for member in OperatingStateRequest]
        assert len(set(values)) == 4

    def test_observed_state_values(self) -> None:
        # Read-side values observed on real controllers; kept as documented
        # constants, not an enum, because the intermediate states vary by
        # firmware and are not pinned.
        assert OPERATING_STATE_STOP_OBSERVED == 4
        assert OPERATING_STATE_RUN_OBSERVED == 8


class TestSetOperatingStateRequestLayout:
    """Byte-exact layout of the (unverified, see #8) OperatingStateREQ write."""

    # Captured from _build_set_operating_state_payload before the IntegrityId is
    # spliced in; the derivation is unvalidated on hardware (issue #8). The only
    # byte that changes between STOP and RUN is the USINT request value.
    STOP = bytes.fromhex("00000034019077000201000004e88969001200000000896a001300896b000400000000000000")
    RUN = bytes.fromhex("00000034019077000203000004e88969001200000000896a001300896b000400000000000000")

    def test_stop_request_is_byte_exact(self) -> None:
        assert _build_set_operating_state_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, OperatingStateRequest.STOP) == self.STOP

    def test_run_request_is_byte_exact(self) -> None:
        assert _build_set_operating_state_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, OperatingStateRequest.RUN) == self.RUN

    def test_only_the_state_value_byte_differs(self) -> None:
        differing = [i for i, (a, b) in enumerate(zip(self.STOP, self.RUN)) if a != b]
        assert len(self.STOP) == len(self.RUN)
        assert differing == [9]  # the USINT value, right after [InObjectId][count][0x877][flags][USINT]
        assert self.STOP[9] == OperatingStateRequest.STOP
        assert self.RUN[9] == OperatingStateRequest.RUN

    def test_structure_targets_cpu_exec_unit_and_operating_state_req(self) -> None:
        payload = _build_set_operating_state_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, OperatingStateRequest.STOP)
        assert payload[:4] == Ids.NATIVE_THE_CPU_EXEC_UNIT_RID.to_bytes(4, "big")
        assert payload[4] == 1  # AddressCount VLQ (single-byte)
        # Attribute 0x877 as a two-byte VLQ, then the USINT PValue header.
        assert payload[5:7] == bytes([0x90, 0x77])
        assert payload[7:9] == bytes([0x00, DataType.USINT])

    def test_reuses_the_plain_set_variable_wrapper(self) -> None:
        # The builder must be the plain SetVariable layout, not a bespoke frame.
        value = bytes([0x00, DataType.USINT]) + bytes([OperatingStateRequest.RUN])
        expected = _build_set_variable_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ, value)
        assert _build_set_operating_state_payload(Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, OperatingStateRequest.RUN) == expected
