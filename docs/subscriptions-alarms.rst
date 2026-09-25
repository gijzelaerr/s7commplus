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
On disconnect or reconnect, local subscriptions are cleared and must be
created again. The synchronous receiver blocks; arrange cancellation by
closing the connection.

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

The asyncio alarm receiver additionally accepts a timeout:

.. code-block:: python

   notification = await client.receive_alarm_notification(timeout=10.0)

Alarm and data notifications are routed to their respective receivers when
the client encounters them on the same connection. Keep one active receive
loop per client so two readers do not consume the same transport stream.
