Getting started
===============

Requirements
------------

``s7commplus`` supports Python 3.10 and newer. Install it from PyPI:

.. code-block:: console

   python -m pip install s7commplus

The PLC must be reachable over TCP, normally on port 102. Rack and slot
arguments are accepted for API symmetry but are not used by S7CommPlus.

First synchronous read
----------------------

Use the context manager so the session is closed even if an operation fails:

.. code-block:: python

   import struct

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10")
       raw = client.db_read(db_number=1, start=0, size=4)
       value = struct.unpack(">f", raw)[0]
       print(value)

``db_read`` returns bytes. Decode those bytes according to the PLC variable's
declared datatype and byte order. A raw byte offset is appropriate for a
non-optimized data block; use symbolic access for optimized blocks.

First asyncio read
------------------

.. code-block:: python

   import asyncio

   from s7commplus import AsyncClient


   async def main() -> None:
       async with AsyncClient() as client:
           await client.connect("192.168.1.10")
           raw = await client.db_read(1, 0, 4)
           print(raw.hex())


   asyncio.run(main())

Handling errors
---------------

Protocol-specific exceptions derive from ``S7Error``. Catch the narrowest
exception that your application can handle:

.. code-block:: python

   from s7commplus import Client
   from s7commplus.error import S7ConnectionError, S7ProtocolError

   try:
       with Client() as client:
           client.connect("192.168.1.10")
           data = client.db_read(1, 0, 4)
   except S7ConnectionError as exc:
       print(f"Connection failed: {exc}")
   except S7ProtocolError as exc:
       print(f"PLC rejected or malformed the request: {exc}")

Before writing
--------------

Confirm the target DB, offset, datatype, and controller state before issuing a
write. Use a disposable test DB on an isolated PLC while developing. Do not
experiment against a production or safety-related controller.
