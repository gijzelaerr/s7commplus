Command-line interface
======================

Installing the package also installs a ``s7commplus`` command, a thin wrapper
around :class:`~s7commplus.Client` for the common field tasks. Every command
takes the connection options first: ``--host`` (required), ``--port``, the
password options described below, and the TLS options ``--tls``, ``--tls-ca``,
``--tls-cert``, ``--tls-key`` and ``--tls-cert-fingerprint`` (alias ``--pin``).
``s7commplus COMMAND --help`` lists them all.

TLS
---

``--tls-ca``, ``--tls-cert``, ``--tls-key`` and ``--tls-cert-fingerprint`` imply
``--tls``: asking for a certificate check never leaves the connection in
plaintext. ``--tls-cert`` and ``--tls-key`` must be given together. With TLS the
PLC certificate's SHA-256 fingerprint is printed to stderr on connect, so you
can copy it into ``--pin``:

.. code-block:: console

   s7commplus state --host 192.168.1.10 --tls
   s7commplus state --host 192.168.1.10 --tls-ca plc-ca.pem
   s7commplus state --host 192.168.1.10 --pin 3f1a...c09e

Passwords
---------

The password is never logged or echoed. Give it in one of these ways, which do
not put it on the command line:

.. code-block:: console

   export S7COMMPLUS_PASSWORD='...'      # read when no password option is given
   s7commplus read --host 192.168.1.10 DB1.Count

   s7commplus read --host 192.168.1.10 --ask-password DB1.Count   # prompts

``--ask-password`` prompts on the terminal without echoing and takes precedence
over ``S7COMMPLUS_PASSWORD``; an empty variable means no password.
``--password VALUE`` also works and overrides the variable (it cannot be combined
with ``--ask-password``), but other users on the machine can see it in the
process list and it stays in the shell history, so keep it for throwaway test
setups.

Browse and read
---------------

.. code-block:: console

   s7commplus browse --host 192.168.1.10
   s7commplus browse --host 192.168.1.10 --json
   s7commplus read --host 192.168.1.10 DB1.Motor.Speed DB1.Count

``browse`` lists each tag as ``name``, wire data type and access sequence.
``read`` decodes each scalar value; ``--json`` emits machine-readable output.
JSON output is strict: raw bytes are hex strings, and a ``REAL``/``LREAL`` that
holds NaN or an infinity, which JSON cannot represent, is ``null``.

Write
-----

.. code-block:: console

   s7commplus write --host 192.168.1.10 DB1.Motor.Speed --real 1.5
   s7commplus write --host 192.168.1.10 DB1.Count --dint 70000
   s7commplus write --host 192.168.1.10 DB1.Flags --hex 0xA1,0x02

A write requires exactly one value encoding: ``--bool``, ``--int`` (2 bytes),
``--dint`` (4 bytes), ``--real`` (4 bytes), ``--string``, or ``--hex`` for raw
big-endian bytes. A value outside the type's range is refused before connecting.

Raw data blocks and state
-------------------------

.. code-block:: console

   s7commplus db-read --host 192.168.1.10 --port 102 1 0 16
   s7commplus db-write --host 192.168.1.10 1 0 --hex deadbeef
   s7commplus state --host 192.168.1.10

``db-read`` prints hex and ``db-write`` takes ``--hex``. ``state`` prints
``RUN``, ``STOP`` or ``UNKNOWN``.

Exit status
-----------

``0``
   Success.
``1``
   The operation failed: a connection, protocol, TLS, certificate or
   authentication error, a certificate or key file that cannot be loaded, or a
   PLC that rejected a read or write (including any tag ``read`` could not read).
``2``
   Usage error: invalid arguments or values, a missing certificate or key file,
   or an unknown tag.
``130``
   Interrupted.
