API reference
=============

Clients
-------

.. autoclass:: s7commplus.Client
   :members:
   :undoc-members:

.. autoclass:: s7commplus.AsyncClient
   :members:
   :undoc-members:

Subscriptions and alarms
------------------------

.. autoclass:: s7commplus.SubscriptionItem
   :members:

.. autoclass:: s7commplus.SubscriptionNotification
   :members:

.. autoclass:: s7commplus.Alarm
   :members:

.. autoclass:: s7commplus.AlarmNotification
   :members:

.. autoclass:: s7commplus.AlarmText
   :members:

.. autoclass:: s7commplus.LanguageId
   :members:

Server emulator
---------------

.. autoclass:: s7commplus.Server
   :members:

.. autoclass:: s7commplus.DataBlock
   :members:

.. autoclass:: s7commplus.CPUState
   :members:

Protocol enums
--------------

.. autoclass:: s7commplus.protocol.DataType
   :members:

.. autoclass:: s7commplus.protocol.AccessLevel
   :members:

Exceptions
----------

.. automodule:: s7commplus.error
   :members: S7Error, S7ConnectionError, S7ProtocolError, S7TimeoutError, S7AuthenticationError, S7RateLimitError
