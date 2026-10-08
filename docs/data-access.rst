Reading, writing, and browsing
==============================

Raw data blocks
---------------

Read and write non-optimized DB regions by byte offset:

.. code-block:: python

   import struct

   from s7commplus import Client
   from s7commplus.protocol import DataType

   with Client() as client:
       client.connect("192.168.1.10")

       temperature = struct.unpack(">f", client.db_read(1, 0, 4))[0]
       client.db_write(
           db_number=1,
           start=4,
           data=struct.pack(">f", 21.5),
           datatype=DataType.REAL,
       )

The write datatype must match the PLC target. ``BLOB`` preserves raw-byte
compatibility but is not a generic replacement for scalar datatypes.

Batch operations
----------------

Batching reduces request overhead and preserves item order:

.. code-block:: python

   from s7commplus.protocol import DataType

   values = client.db_read_multi(
       [
           (1, 0, 4),
           (1, 4, 4),
           (2, 0, 1),
       ]
   )

   client.db_write_multi(
       [
           (1, 0, b"\x00\x00\x00\x2a", DataType.DINT),
           (2, 0, b"\x01", DataType.BOOL),
       ]
   )

``db_read_multi``, ``db_write_multi``, ``read_symbolic_multi``, ``read_tags``
and ``write_tags`` split a large batch over several requests of at most
``client.max_items_per_request`` items (default 100; ``0`` sends a batch in one
request). The requests go out in order and the results come back in item
order. ``db_read_multi`` returns ``b""`` for an item the PLC could not read,
including each item of a request the PLC refused as a whole.

A write split over several requests is not atomic. The PLC writes every item it
does not refuse, and a refused item does not stop the batch: ``db_write_multi``
raises :class:`~s7commplus.error.S7WriteError` after the last request, whose
``item_errors`` maps the 1-based position of each refused item in the whole
batch to its PLC error. A connection, timeout or protocol failure after the
first request stops the batch: ``db_write_multi`` raises ``S7WriteError`` from
that failure, and ``write_tags`` returns its results with that error on every
tag it could not confirm. The error's ``unknown`` positions may or may not have
been written; its ``not_sent`` positions were never sent. A failure of the first
request propagates unchanged, as for a single request.

Controller areas
----------------

``read_area`` and ``write_area`` accept an S7CommPlus area relation ID rather
than a DB number. These lower-level methods are useful when the area ID is
known from browsing or a protocol trace.

Optimized blocks and symbolic access
------------------------------------

Byte offsets are not stable for optimized data blocks. ``browse`` discovers
the symbol tree and returns a flat list containing each variable's name,
datatype, offsets, and ``access_sequence``:

.. code-block:: python

   variables = client.browse()
   for variable in variables:
       print(
           variable["name"],
           variable["data_type"],
           variable["access_sequence"],
       )

An access sequence contains a hexadecimal access-area ID followed by the LID
path. Convert it for ``read_symbolic`` as follows:

.. code-block:: python

   target = next(item for item in variables if item["name"] == "Data_block_1.temperature")
   area_hex, *lid_hex = target["access_sequence"].split(".")

   raw = client.read_symbolic(
       access_area=int(area_hex, 16),
       lids=[int(value, 16) for value in lid_hex],
   )

For application code, the name-based catalog API keeps that address and type
metadata together and uses the PLC datatype when encoding writes:

.. code-block:: python

   import struct

   tag = client.resolve_tag("Data_block_1.temperature")
   print(tag.softdatatype, tag.array_dimensions, tag.symbol_crc)

   raw = client.read_tag(tag.name)
   temperature = struct.unpack(">f", raw)[0]
   client.write_tag(tag.name, struct.pack(">f", 21.5))

``read_tags`` and ``write_tags`` batch multiple names and return one
:class:`~s7commplus.TagResult` per requested item. Inspect ``result.success``,
``result.value``, and ``result.error`` instead of losing successful items when
the PLC rejects another item in the same request:

.. code-block:: python

   results = client.read_tags(
       ["Data_block_1.temperature", "Data_block_1.pressure"]
   )
   for result in results:
       if result.success:
           print(result.tag.name, result.value)
       else:
           print(result.tag.name, result.error)

The catalog is cached for the connection. Call ``refresh_tag_catalog`` to
browse immediately or ``invalidate_tag_catalog`` to force a browse on the next
name lookup. Named reads and writes send SymbolCRC 0, which disables the PLC's
layout check: the ``symbol_crc`` reported by a browse is per-entry type
metadata, not the access-path CRC the PLC validates, and real CPUs reject it.
Failed items are reported per tag and never retried automatically; after a
download that changes the PLC layout, call ``refresh_tag_catalog``. Unknown
names and unsupported PLC datatypes raise before a request is sent.

The async client provides the same methods as coroutines, except
``invalidate_tag_catalog``, which is immediate:

.. code-block:: python

   raw = await client.read_tag("Data_block_1.temperature")
   results = await client.write_tags(
       {"Data_block_1.temperature": struct.pack(">f", 21.5)}
   )

Symbolic browsing and access remain experimental because observable behavior
varies across firmware versions. In particular, physical I/Q/M reads and
symbolic BOOL values can behave differently on some S7-1200 firmware.

CPU state and blocks
--------------------

The clients also expose ``get_cpu_state``, ``set_plc_operating_state``,
``upload_block``, and ``download_block``. State changes and block downloads are
intrusive operations: verify the controller and authorization boundary before
using them.
