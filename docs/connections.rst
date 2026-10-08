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

The clients share transport, TLS, session-setup, SessionKey, and
response-parsing helpers:

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
     - Supported (emulator-tested; not yet validated on hardware)
   * - V2 or V3 with TLS
     - Supported
     - Supported

Both clients authenticate a PLC that advertises legacy public-key fingerprint or
session-challenge attributes. They share the same blob, framing, key-fallback
and renewal logic, and accept the same ``connect()`` options: ``password``,
``allow_legacy_key_fallback``, ``legacy_session_key_refresh_interval`` and
``legacy_s7_1500`` (an override; the profile is automatic). The synchronous path is the one validated on real
controllers; the asyncio path so far runs against the emulator and captured
request layouts only. Password legitimation over a TLS session is also
available through ``authenticate``, and happens during ``connect`` when a
``password`` is given.

Observed firmware and session paths
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The negotiated path depends on firmware and on whether the TIA Portal project
enables secure PG/PC communication (TLS), so a firmware version alone does not
determine it. The following combinations have been reported on real hardware:

.. list-table:: Hardware reports
   :header-rows: 1
   :widths: 34 14 24 28

   * - Controller
     - Firmware
     - Session path
     - Status
   * - S7-1200 CPU 1212C
     - V4.2.2
     - V1, legacy SessionKey
     - Validated
   * - S7-1512SP (6ES7 512-1DK01-0AB0)
     - V2.6
     - V1, legacy SessionKey
     - Validated
   * - S7-1200 CPU 1215C (6ES7 215-1AG40-0XB0)
     - V4.2
     - V1, legacy SessionKey
     - Validated (sync and async, reads and browse; writes untested)
   * - S7-1515-2 PN
     - V2.9
     - V1, legacy SessionKey
     - Not working; session setup is reset
   * - PLCSIM / PLCSIM Advanced (TIA Portal V16 or older)
     - key family 03
     - V1, legacy SessionKey
     - Emulator-tested only; no password legitimation
   * - S7-1200
     - V4.1, V4.5, V4.7.3
     - TLS
     - Working
   * - S7-1500 (e.g. 1511F-1 PN)
     - V2.9.7, V2.9.8
     - TLS
     - Working

Firmware not listed here has not been validated. "V1" in this documentation
refers to the S7CommPlus protocol-version byte negotiated by the session, not
to the protocol generations used in some academic literature.

V1 SessionKey request profile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

S7-1500 firmware 2.6 and S7-1200 firmware V4.2 (1215C) share a request profile
on the non-TLS V1 SessionKey path: authenticated fragment digests, V2 object
qualifiers on data requests, a structured EXPLORE request, the IntegrityId after
the response body, and (S7-1200 key family 01) one skipped IntegrityId after
legitimation. It is selected automatically for every V1 SessionKey session, so
no option is needed:

.. code-block:: python

   from s7commplus import Client

   with Client() as client:
       client.connect("192.0.2.1")
       tags = client.browse()
       tag = next(tag for tag in tags if tag["name"] == "Example.Value")
       address = [int(part, 16) for part in tag["access_sequence"].split(".")]
       raw = client.read_symbolic(address[0], address[1:])

``legacy_s7_1500=False`` forces the classic layout instead, for a controller that
rejects the profile (the S7-1200 CPU 1212C FW V4.2.2 report predates it; please
report if it needs the override). The setting is retained across reconnects and
never applies to TLS or V2/V3 sessions. Writes, alarms and subscriptions with
this profile have not been hardware validated.

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

Timeouts
--------

``connect()`` takes four timeouts in seconds, by keyword:

``timeout`` (default 5)
   bounds the TCP connect and the COTP, InitSSL, TLS and CreateObject
   handshake together.
``request_timeout`` (default: ``timeout``)
   bounds the wait for each reply once the handshake is done, and for each
   further part of a multi-part reply. Raise it for a PLC that is slow on long
   answers.
``explore_timeout`` (default 30; ``None``: the request timeout)
   does the same for the reply to an EXPLORE, which ``browse()``,
   ``list_datablocks()``, ``explore()``, ``get_cpu_state()`` and
   ``read_alarms()`` send, among others. These replies can be large: on a CPU
   1215C (FW V4.2, 54 data blocks, 6802 variables) the type-info EXPLORE of
   ``browse()``, about 111 KB in 111 parts, took 5.9 to 7.0 s in total, where
   a GetMultiVariables took at most 0.52 s. The value is used as given, also
   when ``request_timeout`` is longer.
``notification_timeout`` (default: the request timeout)
   bounds a wait for subscription data or alarms.

.. code-block:: python

   client.connect("192.168.1.10", timeout=5.0, request_timeout=15.0, explore_timeout=60.0)

``receive_subscription_notification()`` and ``receive_alarm_notification()``
also take a per-call ``timeout`` that overrides ``notification_timeout``. The
wait bounds the whole call: notifications for other subscriptions that arrive
meanwhile are queued for them and do not extend it. When it runs out, both
clients raise ``S7TimeoutError``. PLCSIM Advanced (V8.0, CPU 1511, FW V2.9;
not checked on hardware) sends a notification every subscription cycle even
when no value changed, so an active subscription with a cycle shorter than the
wait does not run into it. Raise ``notification_timeout`` for longer cycles,
or for alarms, which arrive only when one changes:

.. code-block:: python

   await client.connect("192.168.1.10", notification_timeout=3600.0)

A timeout that is zero, negative or not finite raises ``ValueError``. The
asyncio client bounds every network wait the same way, including a send that
the PLC does not accept within the request timeout, and both clients enable
TCP keepalive, so a silent PLC raises ``S7TimeoutError`` instead of hanging.

What a timeout leaves of the session depends on where it struck:

* A request whose reply does not arrive in time leaves the session in an
  unknown state, so the client closes it (without a DeleteSession exchange)
  and raises ``S7TimeoutError``. It is then handled like a connection the PLC
  dropped: ``connected`` reports ``False``, the next request raises
  ``S7ConnectionError("Not connected")``, and the connect parameters and the
  subscription bookkeeping are kept, so reconnect to go on.
* A read that stops part-way through a frame, or between the parts of a
  multi-part reply, closes the session the same way, whatever it was waiting
  for, because the unread rest would otherwise be taken for the next message.
  In the asyncio client this includes a read cancelled from outside, for
  example by ``asyncio.wait_for()`` around a call.
* A notification wait that runs out before any byte of the next frame arrived
  is clean: the session stays usable.

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
