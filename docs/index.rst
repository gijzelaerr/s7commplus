s7commplus
==========

``s7commplus`` is a pure-Python S7CommPlus client and server emulator for
Siemens S7-1200 and S7-1500 PLCs. It supports S7CommPlus V1, V2 with TLS, and
V3, with synchronous and asyncio clients.

This is an unofficial implementation and is not affiliated with, endorsed by,
or supported by Siemens AG. Test against an isolated controller before using it
in production or safety-relevant environments.

Installation
------------

.. code-block:: console

   pip install s7commplus

Synchronous client
------------------

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10", port=102)
       data = client.db_read(1, 0, 4)
       client.db_write(1, 0, b"\x01\x02\x03\x04")

Asyncio client
--------------

.. code-block:: python

   from s7commplus import AsyncClient

   async with AsyncClient() as client:
       await client.connect("192.168.1.10", port=102)
       data = await client.db_read(1, 0, 4)

API reference
-------------

.. automodule:: s7commplus
   :members:
   :imported-members:
