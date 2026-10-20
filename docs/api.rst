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

.. autoclass:: s7commplus.ProgramObject

.. autoclass:: s7commplus.OperatingStateChange
   :members:

Symbolic tags
-------------

.. autoclass:: s7commplus.SymbolCatalog
   :members:

.. autoclass:: s7commplus.SymbolicTag
   :members:

.. autoclass:: s7commplus.ArrayDimension
   :members:

.. autoclass:: s7commplus.TagResult
   :members:

.. automodule:: s7commplus.values
   :members: decode, encode, assemble, split

Block interfaces
----------------

.. autoclass:: s7commplus.BlockInterface
   :members:

.. autoclass:: s7commplus.Member
   :members:

.. autoexception:: s7commplus.BlockInterfaceError

.. autofunction:: s7commplus.resolve_id_path

.. autofunction:: s7commplus.block_interface_from_explore

.. autofunction:: s7commplus.find_preset_stream

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

Return values
-------------

.. autoclass:: s7commplus.protocol.ReturnValue
   :members:

.. autoclass:: s7commplus.protocol.ServiceResult
   :members:
   :undoc-members:

.. autoclass:: s7commplus.protocol.GenericError
   :members:
   :undoc-members:

.. autoclass:: s7commplus.protocol.ErrorSource
   :members:
   :undoc-members:

.. autoclass:: s7commplus.protocol.OperatingStateRequest
   :members:

Exceptions
----------

Every class below is also importable from ``s7commplus``. ``S7RequestError``,
``S7WriteError``, ``S7SubscriptionError`` and ``S7NotConnectedError`` are also
``RuntimeError`` subclasses.

.. automodule:: s7commplus.error
   :members: S7Error, S7ConnectionError, S7NotConnectedError, S7CertificateError, S7TlsHandshakeError, S7ProtocolError, S7IntegrityError, S7ReturnValueError, S7TimeoutError, S7AuthenticationError, S7RateLimitError, S7WriteError, S7SubscriptionError, S7RequestError
