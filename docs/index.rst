s7commplus
==========

Pure-Python S7CommPlus communication for Siemens S7-1200 and S7-1500
controllers. The package provides synchronous and asyncio clients, symbolic
browsing, subscriptions and alarms, plus a server emulator for tests.

.. important::

   This package implements **S7CommPlus**, not the classic S7 protocol used by
   S7-300/400 controllers and PUT/GET access. Use `python-snap7
   <https://python-snap7.readthedocs.io/>`_ for classic S7 communication.

.. warning::

   This is an unofficial implementation and is not affiliated with, endorsed
   by, or supported by Siemens AG. Validate applications against an isolated,
   non-safety-critical controller before production use.

Start here
----------

Install the package and perform a first read in :doc:`getting-started`. Then
choose the guide that matches the PLC operation you need.

.. toctree::
   :maxdepth: 2
   :caption: User guide

   getting-started
   connections
   data-access
   subscriptions-alarms
   server-emulator

.. toctree::
   :maxdepth: 2
   :caption: Reference

   api
   development

Supported surface
-----------------

* S7CommPlus V1, V2 with TLS, and V3 framing
* synchronous and asyncio clients
* raw DB and controller-area reads and writes
* symbolic browsing and LID-based access for optimized blocks
* data subscriptions, alarm subscriptions, and active-alarm snapshots
* block upload/download and CPU-state operations
* an in-memory server emulator for integration tests

Some firmware-dependent operations are marked experimental in the API
reference. PLC firmware, protection settings, and project configuration can
all affect which services are accepted.
