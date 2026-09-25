"""Regression tests pinning parsers against golden, independently captured TIA frames.

The frames in ``tests/fixtures/golden_tia_online_session_20260915.py`` were
shared upstream in PR #45 (bmappi) from an independent MITM capture between
TIA Portal and a PLCSIM S7-1500. They were not captured or verified by this
project. These tests decode them with this codebase's own parsers and pin
the exact values, so any claim from that capture that does not actually hold
against this library's parsing logic shows up as a test failure rather than
as an unverified comment.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from s7commplus.alarm import parse_alarm_notification
from s7commplus.codec import decode_header
from s7commplus.subscription import parse_subscription_notification

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "golden_tia_online_session_20260915.py"
_spec = importlib.util.spec_from_file_location("golden_tia_online_session_20260915", _FIXTURE_PATH)
assert _spec is not None and _spec.loader is not None
golden = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = golden
_spec.loader.exec_module(golden)


def test_notification_cpu_state_decodes_as_subscription_notification() -> None:
    notification = parse_subscription_notification(golden.notification_cpu_state)

    assert notification.subscription_id == 0x7000103F
    assert notification.credit_tick == 0
    assert notification.sequence_number == 2
    assert notification.change_counter == 2
    assert notification.timestamp_microseconds == 1789505130017193
    # CPU state attributes 3760-3764 (0x9C70-0x9C74); values observed while RUN was active.
    assert notification.values[1] == b"\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00"


def test_notification_sub_events_decodes_as_subscription_notification() -> None:
    notification = parse_subscription_notification(golden.notification_sub_events)

    assert notification.subscription_id == 0x70001040
    assert notification.sequence_number == 531
    assert notification.change_counter == 2
    assert len(notification.values) == 15
    assert notification.errors == {}


@pytest.mark.parametrize("frame_name", ["notification_cpu_state", "notification_sub_events"])
def test_event_notifications_are_rejected_by_the_alarm_parser(frame_name: str) -> None:
    """The alarm and data-subscription notification grammars are not interchangeable."""
    frame = getattr(golden, frame_name)
    with pytest.raises(ValueError):
        parse_alarm_notification(frame)


def test_component_table_response_header_is_well_formed() -> None:
    # This fixture is a short excerpt of a larger response (the header's own
    # declared body length exceeds the bytes captured here), so only the
    # header itself -- not full-frame length -- is checked.
    version, data_length, consumed = decode_header(golden.component_table_resp)
    assert version == 2
    assert consumed == 4
    assert data_length > 0


def test_symbolic_write_response_header_is_well_formed() -> None:
    version, data_length, consumed = decode_header(golden.symbolic_write_resp)
    assert version == 2
    assert len(golden.symbolic_write_resp) == consumed + data_length
    # ReturnValue VLQ (success) is followed by 0x0d here, not the 0x00 seen on
    # a GetVarSubStreamed response -- the byte after ReturnValue is per
    # function code, not a fixed protocol constant.
    body = golden.symbolic_write_resp[consumed:]
    return_value_offset = body.index(b"\x34") + 1
    assert body[return_value_offset] == 0x00  # ReturnValue VLQ: success
    assert body[return_value_offset + 1] == 0x0D
