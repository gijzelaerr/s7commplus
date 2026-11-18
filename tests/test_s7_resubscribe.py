"""Recreating data subscriptions after a reconnect."""

from __future__ import annotations

import struct
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.client import S7CommPlusClient
from s7commplus.codec import encode_header
from s7commplus.protocol import DataType, Opcode, ProtocolVersion
from s7commplus.subscription import SubscriptionItem, SubscriptionNotification, parse_subscription_notification
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq

OLD_FIRST = 0x70400025
OLD_SECOND = 0x70400026
NEW_FIRST = 0x70400031
NEW_SECOND = 0x70400032


def _created(subscription_id: int) -> bytes:
    return encode_uint64_vlq(0) + b"\x01" + encode_uint32_vlq(subscription_id)


def _rejected() -> bytes:
    return encode_uint64_vlq(0x8001)  # non-zero return value, no object ids


def _notification_frame(subscription_id: int, change_counter: int = 1) -> bytes:
    data = bytearray([Opcode.NOTIFICATION])
    data += struct.pack(">IHHH", subscription_id, 4, 0, 0)
    data += bytes([3]) + encode_uint32_vlq(1) + bytes([change_counter])
    data += b"\x9b" + encode_uint32_vlq(8) + bytes([0, DataType.USINT, 0x2A])
    data += b"\x13" + struct.pack(">I", 9) + b"\x00\xaa"
    return encode_header(ProtocolVersion.V2, len(data)) + bytes(data) + bytes([0x72, 2, 0, 0])


def _counter(client: Any, subscription_id: int) -> int:
    return int(client._subscriptions._states[subscription_id].change_counter)


def _sync_client(*responses: bytes) -> tuple[S7CommPlusClient, MagicMock]:
    connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    connection.send_request.side_effect = list(responses)
    client = S7CommPlusClient()
    client._connection = connection
    return client, connection


def _recording_requests(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[dict[str, Any]]:
    recorded: list[dict[str, Any]] = []
    real = module.build_subscription_request

    def build(container_id: int, items: Any, **kwargs: Any) -> Any:
        recorded.append({"items": list(items), **kwargs})
        return real(container_id, items, **kwargs)

    monkeypatch.setattr(module, "build_subscription_request", build)
    return recorded


def test_sync_resubscribe_recreates_every_subscription_with_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    import s7commplus.client as client_module

    client, _ = _sync_client(_created(OLD_FIRST), _created(OLD_SECOND))
    first = client.create_subscription(["8A0E0007.A"], cycle_ms=250, credit_limit=20, credit_step=7, queue_size=3)
    second = client.create_subscription(["8A0E0007.B", "8A0E0007.C"], cycle_ms=1000, credit_limit=-1, queue_size=9)
    delivered: list[SubscriptionNotification] = []
    client.add_subscription_callback(first, delivered.append)
    items = {first: list(client._subscriptions._states[first].items.values())}

    client.disconnect()  # the same clear a reconnect does
    with pytest.raises(KeyError):
        client.subscription_diagnostics(first)

    new_client_connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    new_client_connection.send_request.side_effect = [_created(NEW_FIRST), _created(NEW_SECOND)]
    client._connection = new_client_connection
    recorded = _recording_requests(monkeypatch, client_module)

    result = client.resubscribe()

    assert result.restored == {first: NEW_FIRST, second: NEW_SECOND}
    assert result.failed == {}
    assert [(r["cycle_ms"], r["credit_limit"]) for r in recorded] == [(250, 20), (1000, -1)]
    assert recorded[0]["items"] == items[first]
    assert [item.lids for item in recorded[1]["items"]] == [(0xB,), (0xC,)]
    states = client._subscriptions._states
    assert (states[NEW_FIRST].queue_size, states[NEW_FIRST].credit_step) == (3, 7)
    assert states[NEW_SECOND].queue_size == 9

    # The callback follows the subscription to its new ID; the old ID is dead.
    notification = parse_subscription_notification(_notification_frame(NEW_FIRST, _counter(client, NEW_FIRST)))
    assert client._subscriptions.route(notification)[0] is True
    assert len(delivered) == 1
    stale = parse_subscription_notification(_notification_frame(OLD_FIRST))
    assert client._subscriptions.route(stale) == (False, None)
    assert client._subscriptions.pending_restore == ()


def test_sync_resubscribe_reports_a_rejected_subscription_and_keeps_it_pending() -> None:
    client, _ = _sync_client(_created(OLD_FIRST), _created(OLD_SECOND))
    first = client.create_subscription(["8A0E0007.A"])
    second = client.create_subscription(["8A0E0007.B"])
    client.disconnect()

    connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    connection.send_request.side_effect = [_rejected(), _created(NEW_SECOND)]
    client._connection = connection

    result = client.resubscribe()

    assert result.restored == {second: NEW_SECOND}
    assert list(result.failed) == [first]
    assert isinstance(result.failed[first], RuntimeError)
    assert [spec.subscription_id for spec in client._subscriptions.pending_restore] == [first]

    connection.send_request.side_effect = [_created(NEW_FIRST)]
    retry = client.resubscribe()
    assert retry.restored == {first: NEW_FIRST}
    assert retry.failed == {}
    assert client._subscriptions.pending_restore == ()


def test_sync_resubscribe_survives_a_second_disconnect_and_can_be_forgotten() -> None:
    client, _ = _sync_client(_created(OLD_FIRST))
    first = client.create_subscription(["8A0E0007.A"])
    client.disconnect()
    client.disconnect()  # nothing live: must not forget the first clear's subscriptions
    assert [spec.subscription_id for spec in client._subscriptions.pending_restore] == [first]

    client.forget_lost_subscriptions()
    assert client._subscriptions.pending_restore == ()
    client._connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    assert client.resubscribe().restored == {}
    client._connection.send_request.assert_not_called()


def test_sync_deleted_subscriptions_are_not_restored() -> None:
    client, _ = _sync_client(_created(OLD_FIRST), b"")
    first = client.create_subscription(["8A0E0007.A"])
    client.delete_subscription(first)
    client.disconnect()
    assert client._subscriptions.pending_restore == ()


def test_resubscribe_without_a_connection_fails_per_subscription_and_keeps_them_pending() -> None:
    client, _ = _sync_client(_created(OLD_FIRST))
    first = client.create_subscription(["8A0E0007.A"])
    client.disconnect()

    result = client.resubscribe()  # not connected

    assert result.restored == {}
    assert isinstance(result.failed[first], RuntimeError)
    assert [spec.subscription_id for spec in client._subscriptions.pending_restore] == [first]


def _async_client() -> S7CommPlusAsyncClient:
    client = S7CommPlusAsyncClient()
    client._connection._connected = True
    client._connection._reader = MagicMock()
    client._connection._writer = MagicMock()
    client._connection._subscription_container_id = 0x3C2
    client._connection._protocol_version = ProtocolVersion.V2
    return client


@pytest.mark.asyncio
async def test_async_resubscribe_recreates_subscriptions_and_reports_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    import s7commplus.async_client as client_module

    client = _async_client()
    client._connection._send_request = AsyncMock(side_effect=[_created(OLD_FIRST), _created(OLD_SECOND)])
    first = await client.create_subscription(["8A0E0007.A"], cycle_ms=250, credit_limit=20, queue_size=4)
    second = await client.create_subscription([SubscriptionItem.from_access_sequence("8A0E0007.B")], cycle_ms=500)
    delivered: list[SubscriptionNotification] = []
    client._subscriptions.add_callback(first, delivered.append)

    client._subscriptions.clear()  # what _close() does when the session ends
    client._connection._send_request = AsyncMock(side_effect=[_created(NEW_FIRST), _rejected()])
    recorded = _recording_requests(monkeypatch, client_module)

    result = await client.resubscribe()

    assert result.restored == {first: NEW_FIRST}
    assert list(result.failed) == [second]
    assert [(r["cycle_ms"], r["credit_limit"]) for r in recorded] == [(250, 20), (500, 10)]
    assert client._subscriptions._states[NEW_FIRST].queue_size == 4
    assert (
        client._subscriptions.route(parse_subscription_notification(_notification_frame(NEW_FIRST, _counter(client, NEW_FIRST))))[
            0
        ]
        is True
    )
    assert len(delivered) == 1

    client._connection._send_request = AsyncMock(side_effect=[_created(NEW_SECOND)])
    assert (await client.resubscribe()).restored == {second: NEW_SECOND}
    assert client._subscriptions.pending_restore == ()


@pytest.mark.asyncio
async def test_async_close_remembers_subscriptions_and_disconnect_keeps_them() -> None:
    client = _async_client()
    client._connection._send_request = AsyncMock(side_effect=[_created(OLD_FIRST)])
    first = await client.create_subscription(["8A0E0007.A"])

    await client._connection._close()
    await client.disconnect()

    assert [spec.subscription_id for spec in client._subscriptions.pending_restore] == [first]
    client.forget_lost_subscriptions()
    assert client._subscriptions.pending_restore == ()


# A PLC may hand the same subscription ID to the recreated subscription. Nothing
# received before the reconnect may reach it.


def test_sync_resubscribe_with_a_reused_id_drops_what_arrived_before_the_reconnect() -> None:
    client, _ = _sync_client(_created(OLD_FIRST))
    first = client.create_subscription(["8A0E0007.A"])
    delivered: list[SubscriptionNotification] = []
    client.add_subscription_callback(first, delivered.append)
    counter = _counter(client, first)

    # One notification is already queued for the caller; another is buffered
    # because its subscription was not registered when it arrived.
    assert client._subscriptions.route(parse_subscription_notification(_notification_frame(first, counter)))[0] is True
    next_counter = counter % 0xFF + 1  # the counter the recreated subscription will carry
    client._subscriptions._orphans.append(parse_subscription_notification(_notification_frame(first, next_counter)))
    assert len(delivered) == 1

    client.disconnect()  # the same clear a reconnect does
    connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    connection.send_request.side_effect = [_created(OLD_FIRST)]  # the PLC reuses the ID
    client._connection = connection

    result = client.resubscribe()

    assert result.restored == {first: first}
    assert client._subscriptions.pending_restore == ()
    assert client._subscriptions.pop(first) is None  # nothing from the old session was carried over
    assert client.subscription_diagnostics(first).queued_notifications == 0
    assert len(delivered) == 1  # the buffered stale notification was not delivered either

    fresh = parse_subscription_notification(_notification_frame(first, _counter(client, first)))
    assert client._subscriptions.route(fresh)[0] is True
    assert len(delivered) == 2  # the callback followed the subscription and fires once per notification


@pytest.mark.asyncio
async def test_async_resubscribe_with_a_reused_id_drops_what_arrived_before_the_reconnect() -> None:
    client = _async_client()
    client._connection._send_request = AsyncMock(side_effect=[_created(OLD_FIRST)])
    first = await client.create_subscription(["8A0E0007.A"])
    delivered: list[SubscriptionNotification] = []
    client._subscriptions.add_callback(first, delivered.append)
    counter = _counter(client, first)
    assert client._subscriptions.route(parse_subscription_notification(_notification_frame(first, counter)))[0] is True
    next_counter = counter % 0xFF + 1  # the counter the recreated subscription will carry
    client._subscriptions._orphans.append(parse_subscription_notification(_notification_frame(first, next_counter)))

    client._subscriptions.clear()  # what _close() does when the session ends
    client._connection._send_request = AsyncMock(side_effect=[_created(OLD_FIRST)])

    result = await client.resubscribe()

    assert result.restored == {first: first}
    assert client._subscriptions.pop(first) is None
    assert len(delivered) == 1
    fresh = parse_subscription_notification(_notification_frame(first, _counter(client, first)))
    assert client._subscriptions.route(fresh)[0] is True
    assert len(delivered) == 2


def test_resubscribe_ignores_a_notification_for_a_subscription_that_was_not_restored() -> None:
    client, _ = _sync_client(_created(OLD_FIRST), _created(OLD_SECOND))
    first = client.create_subscription(["8A0E0007.A"])
    second = client.create_subscription(["8A0E0007.B"])
    client.disconnect()
    connection = MagicMock(subscription_container_id=0x3C2, protocol_version=ProtocolVersion.V2)
    connection.send_request.side_effect = [_created(NEW_FIRST), _rejected()]
    client._connection = connection

    result = client.resubscribe()

    assert result.restored == {first: NEW_FIRST}
    assert list(result.failed) == [second]
    # The rejected subscription has no live ID, so a late frame for its old ID
    # reaches no queue and no callback.
    late = parse_subscription_notification(_notification_frame(second))
    assert client._subscriptions.route(late)[0] is False
    assert client._subscriptions.contains(second) is False
