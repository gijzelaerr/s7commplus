Subscriptions and alarms
========================

Data subscriptions
------------------

The synchronous client can subscribe to symbolic variables using access
sequences returned by ``browse``:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10")
       variables = client.browse()
       sequences = [item["access_sequence"] for item in variables[:2]]

       subscription_id = client.create_subscription(sequences, cycle_ms=100)
       try:
           notification = client.receive_subscription_notification()
           print(notification.values)
           print(notification.errors)
       finally:
           client.delete_subscription(subscription_id)

For explicit symbol CRCs, sub-areas, or stable reference IDs, construct
``SubscriptionItem`` instances instead of passing strings.

Receiving a notification blocks. Run that call in a worker appropriate for
your application and arrange cancellation by closing the connection.

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

Do not run alarm and data-subscription receive loops concurrently on the same
connection. Mixed notification dispatch is not currently supported.
