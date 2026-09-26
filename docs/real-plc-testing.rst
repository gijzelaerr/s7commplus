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

S7-1200 firmware V4.5+ and S7-1500 firmware V2.x+ use S7CommPlus V2 and require
TLS. Pass ``--plc-use-tls`` for those controllers. If the PLC requires custom
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
