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
