Real-PLC acceptance testing
===========================

The versioned Gherkin specifications in ``tests/features/real_plc`` exercise
S7CommPlus connection lifecycle, canonical byte-offset reads, multi-reads, and
safely restored scratch writes. ``pytest-bdd`` keeps pytest as the runner while
producing readable terminal, JUnit XML, and sanitized JSON evidence.

Safety model
------------

Use only a dedicated, non-production, non-safety-critical PLC. The default
runner selects ``@smoke`` and is read-only. Scratch writes require
``--allow-write``, a separate disposable DB (DB2 by default), and a guard that
saves, restores, and reads back the original bytes even when a scenario fails.
Hard process termination or power loss cannot run cleanup, so inspect the
scratch DB before reuse after either event.

Administrative actions require ``--allow-admin`` and must never target an
in-service PLC. No administrative scenarios are included in the initial suite.

PLC preparation
---------------

Import ``tests/plc_setup/e2e_test_dbs.scl`` into TIA Portal, or recreate its
exact layout. It defines read-only DB1 and scratch DB2. Disable ``Optimized
block access`` for both DBs so the byte offsets match the versioned fixture.
Defaults are rack 0, slot 1, and TCP port 102. Apply the least privilege that
permits the selected scenarios.

Pass ``--plc-use-tls`` for controllers configured for secure PG/PC
communication. Newer firmware (for example S7-1200 V4.5+ and S7-1500 V2.9+)
typically uses TLS, but older or legacy-configured controllers, such as an
S7-1200 on V4.2 or an S7-1512SP on V2.6, use the non-TLS V1 SessionKey path.
See :doc:`connections` for the firmware combinations reported so far. If the PLC requires custom
client credentials or CA verification, also pass ``--plc-tls-cert``,
``--plc-tls-key``, and/or ``--plc-tls-ca``. Certificate paths and the PLC
address are used for the connection but are redacted from reports; reports only
record whether TLS, a client certificate, and CA verification were enabled.

Running and reporting
---------------------

Run this acceptance suite from a development checkout; it is not included in
the stable PyPI installation. Install the test extras, then run the safe TLS
profile. Reportable metadata must not contain addresses, credentials,
certificate paths, plant names, or site identifiers:

.. code-block:: console

   python -m pip install -e '.[test]'
   python tools/run_real_plc_acceptance.py \
     --plc-ip YOUR_PRIVATE_ADDRESS \
     --plc-use-tls \
     --tester @YOUR_HANDLE \
     --plc-family S7-1500 \
     --plc-model "CPU 1511F-1 PN" \
     --plc-firmware V2.9.7 \
     --plc-security-mode "S7CommPlus V2 with TLS"

For a custom certificate setup, append paths that exist only on the test host:

.. code-block:: console

   --plc-tls-cert /secure/client.pem \
   --plc-tls-key /secure/client-key.pem \
   --plc-tls-ca /secure/plc-ca.pem

The runner writes JUnit XML and schema-versioned JSON beneath
``real-plc-results/``. It replaces the tester machine's JUnit ``hostname``
attribute with ``redacted`` after pytest finishes. Review both artifacts for
other identifying or sensitive content before publishing them. Add
``--allow-write`` only after confirming DB2 is disposable scratch space.

By default every scenario runs twice, once with ``Client`` and once with
``AsyncClient``; ``--client sync`` or ``--client async`` selects one. Pass
``--expected-cpu-state RUN`` (or ``STOP``) to check the reported CPU state;
without it the state is only recorded.

For a password-protected PLC, put the password in the
``S7COMMPLUS_TEST_PASSWORD`` environment variable. There is deliberately no
command-line option for it, so it stays out of the shell history and the
process list. The value is redacted from both artifacts. The runner selects the
``@password`` scenarios only when the variable is set, and the ``@tls``
scenarios only with ``--plc-use-tls``, so a run never reports ``partial``
merely because it was not configured for them. The wrong-password scenario is
``@administrative``, because repeated failed logins may raise security events
or lock the PLC.

Scenarios
---------

Each feature file in ``tests/features/real_plc`` covers one area. Tags decide
when a scenario runs:

``@smoke``
   Read-only; runs by default.
``@write``
   Changes DB2 and restores it; needs ``--allow-write``.
``@administrative``
   May disturb the PLC; needs ``--allow-admin``.
``@tls`` / ``@password``
   Need ``--plc-use-tls`` / ``S7COMMPLUS_TEST_PASSWORD``.
``@pending``
   Tests an API from an open pull request; needs ``--include-pending``, and is
   skipped with the pull request named until the checkout has that API.

The features are:

- ``connection.feature``: connect, record the negotiated protocol, and read the
  CPU operating state.
- ``lifecycle.feature``: reconnect after a clean disconnect, repeated reads, and
  ``reconnect()`` (``@pending``).
- ``read.feature``: byte-offset reads of DB1, single and multi-item.
- ``write.feature``: byte-offset and named round-trips on DB2, restored and
  verified afterwards.
- ``symbolic.feature``: list the data blocks, browse DB1 (names, types and byte
  offsets against the documented layout), and read every DB1 member by name.
  Members are found by their DB's access area and member name, so the DB names
  in TIA Portal do not matter.
- ``subscriptions.feature``: the initial value of a subscription to DB1 and a
  change notification for a write to DB2.
- ``alarms.feature``: the active-alarm snapshot and an alarm subscription. No
  alarm needs to be active.
- ``security.feature``: TLS is active when requested, a PLC certificate is
  refused against a freshly generated CA, password legitimation, a wrong
  password, and certificate pinning (``@pending``).

Checking the scenarios without a PLC
------------------------------------

CI runs every scenario against in-memory fake clients
(``tests/real_plc/fake_plc.py``) in ``tests/test_real_plc_dry_run.py``, for
both clients and with every opt-in enabled. That catches a step without a
binding or step code that no longer matches the client API before it reaches
a volunteer. It proves nothing about the protocol; only a run against a PLC
does. To run it by hand:

.. code-block:: console

   S7COMMPLUS_TEST_PASSWORD=dry-run pytest tests/real_plc/test_acceptance.py \
     -p tests.real_plc.fake_plc --e2e --allow-plc-write --allow-plc-admin \
     --plc-use-tls --plc-client both

Result policy
-------------

File one ``Real PLC test result`` issue per tester, PLC configuration, source
revision, and run. Attach both generated artifacts and classify the result as
``pass``, ``fail``, or ``partial``. ``pass`` means every selected applicable
scenario passed. ``fail`` means at least one selected scenario failed.
``partial`` means capability skips or an incomplete selection.

Reruns get a new issue and link the earlier result. Close an earlier issue as
superseded only after replacement artifacts exist. A result becomes stale when
the tested code, feature schema, relevant protocol implementation, firmware, or
PLC configuration changes—not merely with age.

For a release candidate, prioritize both an S7-1200 and S7-1500 on representative
firmware and security modes. Hosted CI covers supported Python versions without
hardware; real-PLC evidence stays in issues.

Field notes for hardware sessions
---------------------------------

Two wire behaviors worth knowing before debugging against real hardware,
from independent TIA Portal capture analysis against a PLCSIM S7-1500:

SystemEvent frames (protocol byte 0x72 with version byte 0xFE) show up in two
shapes. A short frame with no payload content is an end of stream marker for
the current response. A content bearing frame is a real event, for example the
diagnostic slot tables an S7-1500 pushes after a diagnostic subscription
create or after the final session teardown. Response collection should only
treat the short shape as a terminator, otherwise it truncates valid responses
that arrive behind such an event.

Expect the PLC to push traffic you did not ask for while a subscription
exists. A fresh S7-1500 session with the diagnostic subscription registered
produces CPU state notifications on one rid and event state notifications on
another, plus SystemEvents around session lifecycle changes. A capture tool
that only pairs requests with responses will show these as unsolicited noise.
They are normal.
