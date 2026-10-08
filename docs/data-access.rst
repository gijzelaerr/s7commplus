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

``refresh_caches_if_program_changed()`` checks before rebuilding: it compares the
PLC's data-block list with the one the catalog was built from and, if that is
unchanged, each cached data block's type-info modification time (one small
EXPLORE per block), and rebuilds the catalog only when something changed. A
recorded time that no longer answers counts as a change, since a download may
have replaced the type-info object. The check narrows the window in which a
stale address is used; it does not close it:

- a change confined to a nested UDT or the PLC tag table may not show in the
  block's own modification time;
- an instance DB moved to another FB keeps its name, number and RID, and only
  its old type-info object is checked;
- a block whose time the PLC does not report is checked by block list only (the
  time was seen only on PLCSIM Advanced V8.0, CPU 1511, FW V2.9).

So call ``refresh_tag_catalog()`` after a known download, and
``refresh_caches_if_program_changed()`` before writing after a possible one: a
write to a stale address can succeed on whatever variable is there now.

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
