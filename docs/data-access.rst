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

Symbolic browsing and access remain experimental because observable behavior
varies across firmware versions. In particular, physical I/Q/M reads and
symbolic BOOL values can behave differently on some S7-1200 firmware.

CPU state and blocks
--------------------

The clients also expose ``get_cpu_state``, ``set_plc_operating_state``,
``upload_block``, and ``download_block``. State changes and block downloads are
intrusive operations: verify the controller and authorization boundary before
using them.
