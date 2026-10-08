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
``client.max_items_per_request`` items (default 50; ``0`` sends a batch in one
request). A CPU 1215C FW V4.2 refuses a read of more than 50 items, whatever its
size. The requests go out in order and the results come back in item
order. ``db_read_multi`` returns ``b""`` for an item the PLC could not read,
including each item of a request the PLC refused as a whole.

They also keep each request frame within ``client.max_request_bytes`` (default
900; ``0`` disables the check). The frame is counted from the S7CommPlus frame
header to its trailer: the 14-byte request header, the payload, the IntegrityId
at its 5-byte maximum and, on a V1 SessionKey session, the 33-byte HMAC. The TLS
record, COTP and TPKT around it are not counted. A larger request makes the PLC
drop the connection: on PLCSIM Advanced V8 (CPU 1511, FW V2.9) a read with a
1034-byte payload (a frame of about 1060 bytes) did, while one with an 834-byte
payload (about 860 bytes) was answered. Real hardware has not been measured. An
item too large for one request on its own, such as a long string or byte block,
raises ``ValueError`` before anything is sent; write it in parts, or raise the
limit for a PLC that accepts larger requests.

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
Failed items are reported per tag and not retried automatically unless
``auto_refresh_tags`` is set (see below); after a download that changes the PLC
layout, call ``refresh_tag_catalog``. Unknown
names and unsupported PLC datatypes raise before a request is sent.

Raw values use the layout a read returns. A STRING is written as the bytes
``[max length, length, characters...]`` and a WSTRING the same as big-endian
UINTs, both padded with zeros to the declared length (``tag.string_length``),
and a DATE_AND_TIME as its eight BCD bytes. ``write_tags`` sends a CHAR as a
USINT, a STRING and a WSTRING as USINT and UINT arrays of that layout, and a
DATE_AND_TIME as an array of its eight bytes. PLCSIM Advanced V8 (CPU 1511,
FW V2.9 with TLS and FW V2.8 without) refused the forms earlier versions sent
and accepts these, and they read back correctly; they are verified on PLCSIM
only, not on a hardware PLC.

To send the forms of earlier versions instead, set
``client.legacy_write_forms = True``: a CHAR as a BYTE, a STRING or WSTRING as
an S7STRING or WSTRING PValue of the value's bytes exactly as given, and a
DATE_AND_TIME as a TIMESTAMP of its eight bytes. That is the behaviour of
0.2.0, which PLCSIM refused and which has not been checked on a hardware PLC
either. On a real PLC, try either form on a disposable tag first.

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
  time was seen on PLCSIM Advanced V8.0, CPU 1511, FW V2.9, and on a CPU 1215C,
  FW V4.2, where 12 of 54 data blocks did not report it).

So call ``refresh_tag_catalog()`` after a known download, and
``refresh_caches_if_program_changed()`` before writing after a possible one: a
write to a stale address can succeed on whatever variable is there now.

Set ``client.auto_refresh_tags = True`` to run that check automatically when a
tag read reports a failed item or a name is not in the catalog. If the program
changed, the client rebuilds the catalog and resolves and reads the names again,
once. The check runs at most once per call, not when the call has just browsed
the catalog, and not within 10 seconds of the previous automatic check, so a tag
that keeps failing or a misspelt name does not add 1 + N requests (N data
blocks) to every poll. A failed read carries no PLC error code, so any failure
triggers it. A write that reached the PLC is never resent, because a stale
address may already have written another variable; only an unknown name, before
anything is sent, is re-resolved.

The async client provides the same methods as coroutines, except
``invalidate_tag_catalog``, which is immediate:

.. code-block:: python

   raw = await client.read_tag("Data_block_1.temperature")
   results = await client.write_tags(
       {"Data_block_1.temperature": struct.pack(">f", 21.5)}
   )

Typed values
~~~~~~~~~~~~

``read_value`` and ``write_value`` work with Python values instead of raw
bytes. A name can be a single tag, or a struct, UDT instance, DTL or array:
those are read as one batch of all their leaves (split over several requests
like ``read_tags`` when it is large) and returned as a ``dict`` or ``list`` (a
DTL as a ``datetime``), and written back the same way:

.. code-block:: python

   import datetime

   temperature = client.read_value("Data_block_1.temperature")   # float
   recipe = client.read_value("Data_block_1.recipe")             # dict
   client.write_value("Data_block_1.temperature", 21.5)
   client.write_value("Data_block_1.recipe", {"speed": 120})     # only this member
   client.write_value("Data_block_1.stamp", datetime.datetime.now())  # a DTL

   speed, setpoints = client.read_values(["Data_block_1.recipe.speed", "Data_block_1.setpoints"])
   client.write_values({"Data_block_1.setpoints": [1.0, 2.0, 3.0], "Data_block_1.on": True})

The values map as follows:

==================================================  ==========================================
PLC type                                            Python value
==================================================  ==========================================
BOOL                                                ``bool``
integers, BYTE, WORD, DWORD, LWORD                  ``int``
REAL, LREAL                                         ``float``
CHAR, WCHAR, STRING, WSTRING                        ``str`` (CHAR and STRING as Latin-1)
DATE                                                ``datetime.date``
TIME, LTIME, S5TIME                                 ``datetime.timedelta``
TIME_OF_DAY, LTOD                                   ``datetime.time`` (naive)
DATE_AND_TIME, LDT, DTL                             ``datetime.datetime`` (naive)
struct, UDT                                         ``dict`` of members
ARRAY                                               ``list`` (nested lists per dimension)
==================================================  ==========================================

A list's first element is the array's declared lower bound, so ``[-2..2]``
reads as five elements. When writing, a ``dict`` may give only some members and
an array may be given as a ``dict`` of index to value; a ``list`` must hold every
element. Nanosecond types (LTIME, LTOD, LDT, DTL) are truncated to the
microseconds Python's types hold; write an ``int`` of nanoseconds (milliseconds
for TIME, TIME_OF_DAY and S5TIME) to set an exact value.

No PLC date or time type stores a time zone. Values are read as naive
``datetime`` and ``time`` objects, and writing an aware one raises
``ValueError`` instead of silently shifting or dropping its offset; convert it
first, for example with ``value.astimezone(datetime.timezone.utc).replace(tzinfo=None)``.
The accepted ranges follow the TIA Portal data type documentation (not verified
on hardware): DATE 1990-01-01 to 2168-12-31, DATE_AND_TIME 1990 to 2089, LDT
and DTL 1970-01-01 to 2262-04-11 23:47:16.854775807, STRING up to 254 and
WSTRING up to 16382 characters. REAL and LREAL also take infinities and NaN.

A value the PLC type cannot hold (the wrong type, out of range, carrying a time
zone, or a string longer than its declared length) raises ``TypeError`` or
``ValueError`` naming the leaf before anything is sent, and a PLC rejection
raises ``RuntimeError`` naming the failed tags. Writes are never retried, and a
write batch split over several requests is not atomic, as for ``write_tags``.
Member names that themselves contain ``.`` or ``[`` nest one level deeper than
declared. ``TagResult.tag.decode_value`` and ``SymbolicTag.encode_value``
convert single raw values the same way.

Symbolic browsing and access remain experimental because observable behavior
varies across firmware versions. In particular, physical I/Q/M reads and
symbolic BOOL values can behave differently on some S7-1200 firmware.

CPU state and blocks
--------------------

The clients also expose ``get_cpu_state``, ``set_plc_operating_state``,
``upload_block``, and ``download_block``. State changes and block downloads are
intrusive operations: verify the controller and authorization boundary before
using them.
