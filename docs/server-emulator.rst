Server emulator
===============

The in-memory server is intended for automated tests and protocol development.
It is not a PLC simulator and does not execute a controller program.

Basic example
-------------

.. code-block:: python

   import struct

   from s7commplus import Client, Server

   server = Server()
   server.register_db(
       1,
       {
           "temperature": ("Real", 0),
           "running": ("Bool", 4),
       },
       size=32,
   )
   db = server.get_db(1)
   assert db is not None
   struct.pack_into(">f", db.data, 0, 23.5)

   server.start(host="127.0.0.1", port=11020)
   try:
       with Client() as client:
           client.connect("127.0.0.1", port=11020)
           assert struct.unpack(">f", client.db_read(1, 0, 4))[0] == 23.5
   finally:
       server.stop()

Use an unprivileged, test-specific port and always stop the server in cleanup.
The test suite contains examples covering TLS, protocol versions, session
authentication, subscriptions, and concurrent clients.

TLS emulator
------------

Pass ``use_tls=True`` plus a PEM certificate and key to ``Server.start``. A
client connecting to that server must enable TLS and trust the test CA. Keep
test keys separate from credentials used by real controllers.
