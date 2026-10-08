Subscriptions and alarms
========================

Data subscriptions
------------------

Both clients subscribe to symbolic variables using access sequences from
``browse`` or ``SymbolicTag`` objects from ``refresh_tag_catalog()``. Tags retain
datatype and reference metadata for decoded notifications:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10")
       variables = client.browse()
       sequences = [item["access_sequence"] for item in variables[:2]]

       subscription_id = client.create_subscription(sequences, cycle_ms=100, queue_size=100)
       try:
           notification = client.receive_subscription_notification(subscription_id)
           print(notification.values)
           print(notification.decoded_values)
           print(notification.errors)
           print(client.subscription_diagnostics(subscription_id))
       finally:
           client.delete_subscription(subscription_id)

Raw bytes remain in ``values``. Known scalar catalog tags are decoded in
``decoded_values``; unknown, structured, array, and truncated values remain
bytes. Explicit ``SubscriptionItem`` values can set symbol CRCs, sub-areas,
and stable reference IDs.

The synchronous client also provides ``iter_subscription_notifications`` and
callbacks. The async client provides an async iterator and a queue-like view:

.. code-block:: python

   from s7commplus import AsyncClient

   async with AsyncClient() as client:
       await client.connect("192.168.1.10", use_tls=True)
       catalog = await client.refresh_tag_catalog()
       subscription_id = await client.create_subscription(list(catalog)[:2])
       try:
           queue = client.subscription_queue(subscription_id)
           notification = await queue.get(timeout=10.0)
           print(notification.decoded_values)
       finally:
           await client.delete_subscription(subscription_id)

Finite notification credits are replenished as updates arrive. Queue and
sequence-loss counters are available through ``subscription_diagnostics``.
On disconnect or reconnect, local subscriptions are cleared, because the PLC
releases its subscription objects with the session. After reconnecting, call
``resubscribe()`` to create them again with their items, cycle, credits, queue
size and callbacks. The PLC assigns new IDs, so ``result.restored`` maps each
old ID to its new one (fetch queues and iterators again for the new IDs), and
``result.failed`` holds the error for every subscription the PLC rejected, for
example because a tag was renamed. Those stay pending, so another call retries
them, and ``forget_lost_subscriptions()`` drops them. Notifications from the
gap are not replayed, and alarm subscriptions are not restored. The
synchronous receiver blocks until a notification arrives or its timeout runs
out (see :doc:`connections`).

.. code-block:: python

   client.connect("192.168.1.10")
   result = client.resubscribe()
   for old_id, new_id in result.restored.items():
       print(f"{old_id:#x} is now {new_id:#x}")

The PLC's DeleteObject operation targets the session subscription container.
Deleting one data or alarm subscription therefore clears every subscription
created by that client; recreate the others if they are still needed.

Active alarms
-------------

Read a snapshot without creating a subscription:

.. code-block:: python

   from s7commplus import LanguageId

   alarms = client.read_alarms([LanguageId.ENGLISH_UNITED_STATES])
   for alarm in alarms:
       print(alarm.cpu_alarm_id, alarm.state, alarm.name)

Alarm notifications
-------------------

.. code-block:: python

   subscription_id = client.create_alarm_subscription(
       language_ids=[LanguageId.ENGLISH_UNITED_STATES]
   )
   try:
       notification = client.receive_alarm_notification(
           [LanguageId.ENGLISH_UNITED_STATES]
       )
       for alarm in notification.alarms:
           print(alarm.cpu_alarm_id, alarm.state)
   finally:
       client.delete_alarm_subscription(subscription_id)

Both alarm receivers take a per-call ``timeout`` in seconds; without one they
wait for the ``notification_timeout`` passed to ``connect()``, else the request
timeout, and raise ``S7TimeoutError`` when it runs out:

.. code-block:: python

   notification = client.receive_alarm_notification(timeout=600.0)

Alarm and data notifications are routed to their respective receivers when
the client encounters them on the same connection. Keep one active receive
loop per client so two readers do not consume the same transport stream.

Notification frame anatomy
--------------------------

Notifications arrive as their own frame family (opcode 0x33) pushed by the PLC
on the subscription rid. The shared header after the subscription id carries
three UInt16 fields. Independent TIA captures show the constant pattern
``04 00 00 00 00 00`` there on different subscription objects, so the first
value is a marker (probably a notification format version), not a counter.
The parser skips these bytes.

What follows depends on the notification family:

- Alarm notifications: credit tick, sequence number (VLQ), change counter, and
  a timestamp when the change counter is zero. This is what
  ``parse_alarm_notification`` implements.
- Event and data notifications (what TIA gets from its online status and
  diagnostic event subscriptions): a zero byte, the sequence number (VLQ),
  another zero byte, an 8 byte timestamp block, then the value records. The
  two families look similar but are not interchangeable, so parsers should
  keep them separate.

Diagnostic events (Online and diagnostics view)
-----------------------------------------------

The objects behind TIA's Online and diagnostics view are plain OMS objects and
can be explored and subscribed to like any other object. Under ASRoot, rid 3
is PLCProgram, rid 10 is SWEvents, and the event objects live at rids 101 to
113 (DiagnosticError is 103, StartupEvent is 107, and so on). An EXPLORE of
rid 3 with the TIA attribute set returns the full tree in one response.

Subscribing works the same way as data subscriptions: create the subscription
object, register the watched attributes with SetMultiVariables, and the PLC
pushes notifications on the subscription rid. From the TIA decompile, the
diagnostic buffer TIA renders is the ASLog object (class 2448) with the
attributes LogEntry (2447), LogEntry2 (8062), and HeadPositionIndicator (3693).
