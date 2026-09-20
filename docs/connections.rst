Connections, TLS, and authentication
====================================

Basic connection
----------------

Both clients negotiate the transport, S7CommPlus session, protocol version,
and required session setup. Useful state is exposed after connection:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.168.1.10", port=102)
       print(client.protocol_version)
       print(client.session_id)
       print(client.session_setup_ok)
       print(client.tls_active)
       print(client.protection_level)

If session setup is rejected, ``connect`` raises instead of leaving a
partially usable public client.

TLS
---

Controllers requiring encrypted S7CommPlus communication must be connected
with ``use_tls=True``. Provide a CA file in production so the PLC certificate
is verified. Client certificate and key files can also be supplied when the
controller configuration requires mutual authentication:

.. code-block:: python

   client.connect(
       "192.168.1.10",
       use_tls=True,
       tls_ca="certificates/plc-ca.pem",
       tls_cert="certificates/client.pem",
       tls_key="certificates/client-key.pem",
   )

TLS records are carried inside COTP data frames by the library. Wrapping the
TCP socket in a conventional TLS socket is not equivalent and will encrypt the
wrong protocol layer.

Password authentication
-----------------------

The synchronous client accepts the PLC password during connection:

.. code-block:: python

   with Client() as client:
       client.connect(
           "192.168.1.10",
           use_tls=True,
           tls_ca="certificates/plc-ca.pem",
           password="secret",
       )

The asyncio client separates connection from authentication:

.. code-block:: python

   async with AsyncClient() as client:
       await client.connect(
           "192.168.1.10",
           use_tls=True,
           tls_ca="certificates/plc-ca.pem",
       )
       await client.authenticate("secret")

Never log passwords, session keys, challenges, private keys, or decrypted
authentication material.

Troubleshooting
---------------

``Connection refused``
   Confirm routing, TCP port 102, firewall rules, and that the PLC permits the
   configured communication service.

V2 requires TLS
   Reconnect with ``use_tls=True`` and the correct certificates.

Certificate verification fails
   Check that ``tls_ca`` contains the issuer of the PLC certificate and that
   the hostname or address matches the certificate configuration.

Access is refused after connection
   A successful transport session does not guarantee permission to read or
   write every object. Check ``protection_level`` and authenticate if required.

Unexpected disconnect after symbolic access
   Some firmware resets a session after particular symbolic reads. The
   high-level browse path retries once on a fresh connection, but applications
   should still treat disconnects as recoverable failures.
