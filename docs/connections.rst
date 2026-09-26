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

Client compatibility
--------------------

The clients share transport, TLS, session-setup, and response-parsing helpers,
but legacy SessionKey authentication is currently synchronous-only:

.. list-table:: Authentication support
   :header-rows: 1
   :widths: 42 20 20

   * - Controller/session path
     - ``Client``
     - ``AsyncClient``
   * - V1 without legacy SessionKey attributes
     - Supported
     - Supported
   * - V1 with legacy SessionKey authentication
     - Supported
     - Not supported; ``connect`` raises before session setup
   * - V2 or V3 with TLS
     - Supported
     - Supported

Use the synchronous client for a PLC that advertises legacy public-key
fingerprint or session-challenge attributes. The asyncio client detects those
attributes in the CreateObject response and fails immediately instead of
returning a misleading connected client. Password legitimation over a
supported TLS session remains available through ``AsyncClient.authenticate``.

Legacy S7-1500 firmware 2.6
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An S7-1512SP on firmware 2.6 has been observed to use different authenticated
fragment digests, symbolic-read qualifiers, and EXPLORE response layouts.
For that non-TLS, synchronous path, opt in explicitly:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.0.2.1", use_tls=False, legacy_s7_1500=True)
       tags = client.browse()
       tag = next(tag for tag in tags if tag["name"] == "Example.Value")
       address = [int(part, 16) for part in tag["access_sequence"].split(".")]
       raw = client.read_symbolic(address[0], address[1:])

The setting defaults to ``False`` and is retained across reconnects. It is
incompatible with TLS. It changes synchronous browse and symbolic reads after
SessionKey authentication; writes, alarms, subscriptions, raw DB access, and
other firmware have not been hardware validated with this profile. The
``AsyncClient`` does not support legacy SessionKey authentication.

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
   Independent TIA Portal capture analysis traces a PLC reset right after
   mixed reads, writes, or subscriptions to two request counter problems,
   not a broken request:

   1. Counter jumps. Each request carries a KeyQualifier / IntegrityId counter
      in the payload. Reads use the read counter, writes use the write counter.
      If a request carries a value that is ahead of the session's real counter
      (for example a captured TIA request replayed verbatim), the PLC resets
      the TCP connection on the spot. The library maintains both counters per
      connection, so this only bites when raw captured payloads are replayed.
   2. Writes on the subscription session. TIA never writes symbols over the
      connection that carries the cyclic subscription. It opens a third short
      lived session, writes there, and tears it down. Doing a
      SetVarSubStreamed write on a subscription session gets the connection
      reset even when every byte of the request is correct.

   The high-level browse path retries once on a fresh connection, but
   applications should still treat disconnects as recoverable failures.

Request counters (IntegrityId)
------------------------------

For V2 and newer sessions, every request carries a running counter value in
the payload. The library splices it in before the trailing fill bytes and
keeps one counter per direction:

- read functions (Explore, GetMultiVariables, GetVarSubStreamed) use the read
  counter
- write functions (SetVariable, SetMultiVariables, CreateObject, DeleteObject)
  use the write counter

The counters start at 0 on a fresh session and increment after each request.
The PLC tracks them and rejects jumps, so never replay a captured payload with
its captured counter value on a live session. When building payloads by hand,
leave a 4 byte fill at the tail and let ``send_request`` splice the counter
(the ``integrity_tail`` parameter). TIA puts the counter in the same place, so
a correctly spliced request is byte compatible with the portal.

On the wire the counter value equals TIA's KeyQualifier. In TIA captures it
just looks bigger because the portal session has done more requests before
yours.
