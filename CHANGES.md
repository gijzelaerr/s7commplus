CHANGES
=======

0.3.0 (2026-10-20)
------------------

PLCSIM Advanced is now validated for the V1 SessionKey (key family 03) and TLS
sessions, including password legitimation. Tag values convert to and from Python
types, large batches are split to fit the PLC's request limits, and TLS gains
certificate pinning and an automatic mode. Clients can reconnect, optionally
retrying reads automatically, and every reply now has a configurable deadline.
A `s7commplus` command-line tool is new. Where an entry was verified only on PLCSIM or on a single CPU, it says so.

### Upgrading from 0.2.0

Most applications need no changes. Check the following if you use them:

* `connect()` no longer lets a raw `ssl.SSLError` or socket error escape a TLS
  handshake: catch `S7ConnectionError` instead (the original error is the
  `__cause__`). `use_tls` accepts only `True`, `False` or `"auto"`; any other
  string (such as `"false"`) raises `ValueError` instead of turning TLS on (#98).
* `AsyncClient` raises `S7ConnectionError` when the PLC closes or resets the
  connection during a request, instead of letting `asyncio.IncompleteReadError`
  or an `OSError` such as `ConnectionResetError` escape: catch
  `S7ConnectionError` where you caught those (#122).
* Every reply now has a deadline: 5 s by default for a request
  (`request_timeout`) and 30 s for an EXPLORE (`explore_timeout`). Missing it
  raises `S7TimeoutError` and closes the session; call `connect()` again before
  the next request (a 0.2.0 sync session was unusable at that point too). For a
  slower PLC pass a larger `request_timeout` or `explore_timeout` to `connect()`;
  `explore_timeout=None` gives EXPLOREs the request timeout (#123).
* An async notification wait without a `timeout` no longer waits forever: it
  ends after `notification_timeout`, else the request timeout, and raises
  `S7TimeoutError` instead of `asyncio.TimeoutError`, so catch `S7TimeoutError`.
  Pass a larger `notification_timeout` to `connect()` for long cycles or alarm
  waits. A per-call `timeout` that is zero, negative or not finite raises
  `ValueError` (#123).
* `explore()`, `explore_xml()`, `get_cpu_state()`, `list_datablocks()`,
  `browse()`, `refresh_tag_catalog()` and `read_alarms()` raise
  `S7ReturnValueError` when the PLC answers with an error ReturnValue. Code that
  decoded the ReturnValue from `explore()`'s reply itself, or treated an empty
  result as "not found", should catch it instead. `read_alarms()` and
  `parse_alarm_explore_response()` used to raise `RuntimeError` for this;
  truncated replies still raise `ValueError` (#110).
* `set_plc_operating_state()` raises `NotImplementedError` and sends nothing.
  It never produced a state change you could rely on; read the state with
  `get_cpu_state()` and change it from TIA Portal until #8 is resolved (#115).
* Multi-item reads and writes are split into requests of at most 50 items and
  900 bytes, and a `db_write_multi` or `write_tags` batch split over several
  requests is not atomic. `S7WriteError` is a `RuntimeError`, so existing handlers still catch
  refused writes; keep a batch to one request if it must not be applied in part.
  A single item too large for one request, and a `create_subscription()` over
  `max_request_bytes`, now raise `ValueError` before anything is sent: set
  `max_request_bytes` higher or to `0` for a PLC that accepts larger requests,
  or use `create_subscriptions()` for many items (#100).
* `SubscriptionItem.from_tag()` items now carry `symbol_crc == 0`. To send the
  browsed CRC anyway, build `SubscriptionItem(tag.access_area, tag.lids,
  symbol_crc=tag.symbol_crc, tag=tag)` (#92).

### New features

* `iter_preset_streams()` yields each preset-dictionary zlib stream in an EXPLORE
  payload as a `PresetStream`, in the order the streams appear, and skips streams
  that are empty or fail to decompress (#64). `iter_preset_headers()` yields the
  offset and `PresetIdentity` of each stream without decompressing it.
  `PresetIdentity` names a preset dictionary by `adler`, `kind` and
  `version`, parsed from its file name. `zlib_dicts.ZLIB_DICT_IDENTITIES`
  maps each Adler-32 to one and supersedes `ZLIB_DICT_NAMES`, which is kept
  for compatibility (#64).
* PLCSIM / PLCSIM Advanced (key family 03) **password legitimation**, a manual
  port of HarpoS7's `SolveLegitimateChallengePlcSim`. The family-03 legacy
  authentication shipped in 0.2.0 as emulator-tested only and refused a
  `password`; it is now validated against S7-PLCSIM Advanced V8 (CPU 1511-1 PN,
  NoAccess FW V2.8 project) with the sync and async clients: connect with a
  password, browse, symbolic and byte-offset reads and writes, and data
  subscriptions from access sequences, reaching `protection_level` 1 after
  `LegitimatedLevel1`. Subscriptions to catalog tags were created and deleted
  but got no values in that validation (see the SymbolCRC fix, #92).
  Byte-offset reads/writes are refused on optimized blocks, as on real
  hardware; use symbolic access there (#83, #66).
  A real S7-1200 or S7-1500 is not affected by these family-03 changes, most of
  which are verified on PLCSIM only: the ServerSessionVersion rewrite, skipping
  the session activation and SessionKey renewal, the response IntegrityId
  placement, the legitimation layout and the `write_symbolic`/subscription-delete
  ObjectQualifier version all apply to key family 03 only, so the other families
  send the same requests as in 0.2.0. The one shared change, in the V1 fragment
  HMAC check, only adds a dialect: every response accepted before is accepted as
  before.
* The new `s7commplus.values` module converts raw tag values to Python values
  and back (`decode()`, `encode()`; `SymbolicTag.encode_value()` is new) and
  builds structs and arrays from their leaves (`assemble()`, `split()`).
  Date and time values are naive: no PLC date or time type stores a time zone,
  so an aware `datetime` or `time` raises `ValueError` instead of being shifted
  or stripped. Ranges follow the TIA Portal data type documentation (DATE to
  2168-12-31, LDT and DTL 1970-01-01 to 2262-04-11). A STRING or WSTRING is
  encoded with its declared length (`string_length`), which sets its header and
  padding; when the catalog does not give it (`0`), encoding raises
  `ValueError`. `SymbolCatalog.members()` lists the leaf tags of a
  struct, UDT, DTL or array (#106).
* `Client` and `AsyncClient` can pin a PLC's TLS certificate instead of relying
  on a CA file: pass `tls_cert_fingerprint` (the SHA-256 as hex, separators
  ignored) to `connect()` and the connection is refused unless the PLC presents
  that exact certificate. `peer_certificate_fingerprint()` reads back the
  presented digest, and a mismatch raises `S7CertificateError`. The pin is
  checked right after the TLS handshake, before the session is created or a
  password is sent. A pin without `use_tls=True` is refused with `ValueError`
  before anything is sent, so a pinned certificate is never used in the clear
  (#97).
* `connect(use_tls="auto")` tries TLS first and continues without it only when
  the TLS handshake does not complete and no `tls_cert_fingerprint`, `tls_ca`,
  client certificate or `password` is given. A failure after the handshake is
  never retried in the clear, each fallback is logged as a warning, and every
  reconnect tries TLS first again. With none of those set, `"auto"` is not
  secure against an active attacker: anyone on the network path who resets
  the TLS handshake makes the client continue in plaintext (see the
  connection docs) (#98).
* `read_tags`, `read_symbolic_multi`, `db_read_multi`, `db_write_multi` and
  `write_tags` (both clients) split a large batch over several requests of at
  most `max_items_per_request` items (default 50; `0` sends a batch in one
  request) and return the results in item order. A CPU 1215C FW V4.2 (non-TLS
  V1 SessionKey session) answers a read of 50 items and refuses one of 51 or
  more with return value `0xA027A6000054FFFC`, whatever the request size;
  PLCSIM Advanced V8 (CPU 1511) is limited by the request size instead, and
  S7-1500 hardware has not been measured (#100).
* The same methods keep each request frame within `max_request_bytes` (default
  900; `0` disables the check), counted from the S7CommPlus frame header to its
  trailer with the IntegrityId at its 5-byte maximum and any SessionKey HMAC,
  but without the TLS record, COTP and TPKT. On PLCSIM Advanced V8 (CPU 1511,
  FW V2.9, TLS project) a read with a 1034-byte payload (a frame of about 1060
  bytes) made the PLC drop the connection, and one with an 834-byte payload was
  answered; real hardware has not been measured (#100).
* `create_subscriptions()` (both clients) spreads items over as many
  subscriptions as `max_request_bytes` requires, in order, and returns their
  IDs; reference IDs stay unique across them. If a subscription after the first
  fails, it raises the new `s7commplus.error.S7SubscriptionError`, whose
  `created` lists the subscriptions already created; they stay active (#100).
* `refresh_caches_if_program_changed()` (both clients, opt-in) rebuilds the tag
  catalog when it finds that the PLC program changed: the data-block list
  differs from the one the catalog was built from, or a cached data block's
  type-info modification time (attribute 529) differs or no longer answers. This
  narrows the window in which a cached address names a different variable after
  a download, but does not close it: a change confined to a nested UDT or the PLC
  tag table, an instance DB moved to another FB, or a PLC that does not report
  the time can go unnoticed. Call it before writing after a possible download.
  The modification time was seen on PLCSIM Advanced V8.0 (CPU 1511, FW V2.9)
  and, read-only, on a real CPU 1215C FW V4.2, where 42 of its 54 data blocks
  report it; that it changes on a download is not verified on hardware. The
  attribute's name has a single source, the attribute-id table of Wireshark's
  S7CommPlus dissector, at an unverified line (#101).
* Setting `auto_refresh_tags = True` (both clients, opt-in) runs that check when
  a tag read reports a failed item or a name is unknown and, if the program
  changed, resolves and reads the names again, once. It checks at most once per
  call and once every 10 seconds, so a tag that keeps failing or a misspelt name
  does not add 1 + N requests to every poll. A write that reached the PLC is
  never resent, and a write to a stale address does not trigger the check
  (#101).
* A `s7commplus` command-line tool: `browse`, `read`, `write`, `db-read`,
  `db-write` and `state`, carrying the same connection and TLS options as the
  clients, including certificate pinning (`--pin`, with the PLC certificate's
  fingerprint printed on connect). The TLS options imply `--tls`. The password
  comes from the `S7COMMPLUS_PASSWORD` environment variable, a no-echo
  `--ask-password` prompt or `--password`, and is never logged. `read` decodes
  scalar tags and `--json` emits strict JSON. `-v` sends the library's INFO log
  to stderr and `-vv` its DEBUG log, which holds the raw protocol frames. The
  exit status is 0 on success, 1 when the operation fails, including any
  `ValueError` the library raises once connected, and 2 for a usage error found
  before connecting or an unknown tag (#103).
* `Client.reconnect()` and `AsyncClient.reconnect()` build a new session with the
  parameters of the last `connect()` and legitimate it with the same password; on
  `AsyncClient`, a successful `authenticate()` replaces that password and adds its
  username, while a refused one changes nothing. `connection_generation` counts
  the reconnects. A failed attempt keeps the parameters, so it can be repeated
  once the PLC is back. Data subscriptions lost with the old session stay
  restorable with `resubscribe()`; alarm subscriptions must be created again.
  Reconnects are serialized, and while one runs, other `AsyncClient` tasks' requests
  fail with "Not connected" instead of interleaving with its handshake (#122).
* Opt-in automatic reconnect for reads: with `connect(..., auto_reconnect=True)`
  (keyword-only) or the `auto_reconnect` property, a read that finds the connection
  dropped reconnects and runs once more on the new session. Only `db_read`,
  `db_read_multi`, `read_area`, `read_symbolic`, `read_symbolic_multi`, `read_tag`,
  `read_tags`, `browse` and `get_cpu_state` are retried; writes never are, because
  it is unknown whether the PLC applied a lost write. A read that timed out is
  not retried either (`S7TimeoutError` is not an `S7ConnectionError`); when the
  timeout ended the session, the next call reconnects. A read called from another
  reconnects only through the outermost call. It stands down, raising
  `S7ConnectionError`, while data or alarm subscriptions are live or lost data
  subscriptions await `resubscribe()`. After an automatic attempt the next one
  waits at least one second, and `AsyncClient` tasks that find the same
  connection dropped share one reconnect. Off by default (#122).
* `Client.connect()` and `AsyncClient.connect()` take the keyword-only
  `timeout` (the TCP connect and the COTP, InitSSL, TLS and CreateObject
  handshake together; 5 s by default, as before), `request_timeout` (the
  wait for each reply, and for each further part of a multi-part reply;
  default `timeout`) and `explore_timeout` (the same for the reply to an
  EXPLORE; default 30 s, `None` for the request timeout).
  `S7CommPlusConnection.connect()` takes `request_timeout` and
  `explore_timeout` by keyword. A timeout that is zero, negative or not finite
  raises `ValueError`. The async client now bounds the connect, the
  handshake, every reply and every send, so a silent PLC raises
  `S7TimeoutError` instead of hanging an `await`, and it tunes TCP keepalive
  like the sync client (#123).
* `connect()` on both clients also takes the keyword-only
  `notification_timeout`, the default wait of the notification receivers
  (default: the request timeout); `S7CommPlusConnection.connect()` takes it by
  keyword. The sync `receive_subscription_notification()` and
  `receive_alarm_notification()` gain the per-call `timeout` the async ones
  have, and `S7CommPlusConnection.receive_notification()` takes one too (#123).
* New exceptions in `s7commplus.error`: `S7ReturnValueError` (#110),
  `S7CertificateError` (#97), `S7TlsHandshakeError` (#98), and
  `S7SubscriptionError` and `S7WriteError` (#100).

### Behaviour changes

* `tags_from_explore()` and `block_interface_from_explore()` select their stream
  by dictionary kind instead of a hard-coded Adler-32, so a new version of a
  dictionary, once added to the package, is picked up without code changes.
  The streams picked for the bundled dictionaries are unchanged (#64).
* `SymbolicTag.decode_value()`, and with it subscription `decoded_values`, now
  decodes STRING and WSTRING by their length header (it used to decode the
  header bytes as text), CHAR, WCHAR, the date and time types, and array
  elements, which it used to leave as bytes. Bytes that are not a valid value
  of the type, or lie outside its range, are still returned unchanged (#106).
* A TLS handshake that does not complete now raises the new
  `S7TlsHandshakeError`, and a PLC certificate that fails `tls_ca` verification
  raises `S7CertificateError`, in both clients. Both are `S7ConnectionError`s;
  before, the raw `ssl.SSLError` or socket error escaped `connect()`. `use_tls`
  now accepts only `True`, `False` or `"auto"`; any other string (such as
  `"false"`) is refused with `ValueError` instead of turning TLS on (#98).
* `explore()`, `explore_xml()`, `get_cpu_state()`, `list_datablocks()`,
  `browse()`, `refresh_tag_catalog()` and `read_alarms()` (sync and async) raise
  `S7ReturnValueError` when the PLC returns an error ReturnValue (#110).
* `Client.set_plc_operating_state()` and `AsyncClient.set_plc_operating_state()`
  now raise `NotImplementedError` and send nothing. They sent an unvalidated
  request whose state numbering differed from the PLC's, and they never checked
  the answer (#115, #8).
* Multi-item reads and writes (`read_tags`, `read_symbolic_multi`,
  `db_read_multi`, `db_write_multi`, `write_tags`, both clients) are split into
  requests of at most 50 items and 900 bytes. A batch that used to go out in
  one request may now take several; set `max_items_per_request` or
  `max_request_bytes` to `0` to turn either bound off (#100).
* A `db_write_multi` or `write_tags` batch split over several requests is not
  atomic. The requests go out in order and a refused item does not stop the
  batch; `db_write_multi` then raises the new `s7commplus.error.S7WriteError`
  after the last request, with `item_errors` keyed by position in the whole
  batch. A connection, timeout or protocol failure after the first request
  stops the batch: `db_write_multi` raises `S7WriteError` from it, and
  `write_tags` returns its results with that error on every tag it could not
  confirm; `unknown` and `not_sent` name the items that may or may not have been
  written and the ones never sent. A failure of the first request propagates
  unchanged (#100).
* `db_read_multi` returns `b""` for each item of a request the PLC refuses as a
  whole, where it returned a shorter list, and raises `RuntimeError` when an
  answer skips or repeats an item, so no value can land on another item. The
  multi-item methods send no request for an empty batch (#100).
* An item too large for one request on its own (for example a `db_write` of a
  long byte block, or a long string in `write_tags`) raises `ValueError` before
  anything is sent, where the request used to go out and the PLC dropped the
  connection (#100).
* `create_subscription()` raises `ValueError` instead of sending a request over
  `max_request_bytes`, which the PLC would answer by dropping the connection; at
  the default that is about 40 to 46 items with a one-level LID path (#100).
* `AsyncClient` raises `S7ConnectionError` when the PLC closes or resets the
  connection during a request, as `Client` already did, instead of letting
  `asyncio.IncompleteReadError` or an `OSError` such as `ConnectionResetError`
  escape. It also ends the session (`connected` turns false), so the next request
  fails at once with "Not connected", and `AsyncClient.browse()` now reconnects on
  firmware that resets the connection after a symbolic read, as `Client.browse()`
  does (#122).
* Every reply now has a deadline, and missing it closes the session.
  Once connected, each reply, and each further part of a multi-part reply,
  must arrive within 5 s by default (`request_timeout`), or within 30 s by
  default (`explore_timeout`) for the reply to an EXPLORE, which `browse()`,
  `list_datablocks()`, `explore()`, `get_cpu_state()` and `read_alarms()`
  send, among others. A reply that misses its deadline raises
  `S7TimeoutError` and closes the session (see the timeout fix under Bug
  fixes and hardening). Before, the async client waited for a reply without
  limit, and the sync client gave every socket read the connect timeout (5 s
  by default), EXPLORE replies included. EXPLORE gets the longer default
  because its replies can be large: on a CPU 1215C (FW V4.2, non-TLS V1
  SessionKey session, 54 data blocks, 6802 variables) the type-info EXPLORE
  that `browse()` sends, about 111 KB in 111 parts, took 5.9 to 7.0 s in
  total over three runs, the other EXPLOREs about 1 s, and a
  GetMultiVariables at most 0.52 s (#123).
* An async notification wait (`receive_subscription_notification()`,
  `receive_alarm_notification()`, `AsyncSubscriptionQueue.get()`) without a
  `timeout` used to wait forever; it now ends after `notification_timeout`,
  else the request timeout (5 s by default), as in the sync client. In both
  clients a notification wait now bounds the whole call rather than each
  frame, so notifications for other subscriptions no longer extend it.
  PLCSIM Advanced (V8.0, CPU 1511, FW V2.9; not checked on hardware) sends a
  notification every subscription cycle even without changes, so an active
  subscription with a short cycle does not run into the default. An expired
  async notification wait raises `S7TimeoutError` instead of
  `asyncio.TimeoutError`, and a per-call `timeout` that is zero, negative or
  not finite now raises `ValueError`, as the connect timeouts do (#123).

### Bug fixes and hardening

* A multi-fragment V1 SessionKey response whose continuation digests are
  chained feed-forward (`HMAC(key, digest_{n-1} ‖ fragment_n)`, as PLCSIM
  Advanced uses) no longer fails with `Invalid V3 continuation HMAC`. The
  verifier previously accepted only the finalized-state resume dialect; it now
  detects the dialect from the second fragment and accepts either (#83, #66).
* Automatic 25-minute SessionKey renewal is skipped on PLCSIM (key family 03):
  the simulator resets the connection when a new SecurityKey is written to
  address 1830, so a renewal would end a long-lived session (#83, #66).
* PLCSIM Advanced no longer receives the address-323 session activation:
  S7CommPlus reads worked but the next `CreateObject`/`SetMultiVariables`
  (writes, subscriptions, deletes) answered with a fatal SystemEvent and a TCP
  reset. The activation is skipped for key family 03 (#83, #66).
* On a PLCSIM family-03 legacy session, `SET`/`CREATE`/`DELETE_OBJECT` response
  payloads keep their body-leading bytes so the per-item error list parses; the
  response IntegrityId follows the body there (#83, #66).
* On a PLCSIM family-03 session, `Client.write_symbolic`/`AsyncClient.write_symbolic`
  and the subscription delete use the session's `object_qualifier_version` like
  every other data path, instead of the negotiated protocol version. Other PLCs
  keep the negotiated version these two requests have always used (#83, #66).
* PLCSIM family-03 sessions rewrite ServerSessionVersion elements 315–318 to the
  real-PLC values in the session setup. Echoing PLCSIM's own values back was
  accepted for the setup and reads, but it made the post-auth legitimation fail;
  the real-PLC values work for both (#83, #66).
* The V1 legitimation `SET_VAR_SUBSTREAMED` request uses PLCSIM's captured layout
  (object qualifier key 1, no item-number byte, the IntegrityId before the
  trailing fill) for key family 03 only. The previous item-number byte made
  PLCSIM reject the request with a fatal SystemEvent. The other families keep the
  pre-existing layout byte-for-byte (#83, #66).
* Every data response the PLC splits over several PDUs is now reassembled,
  not only Explore; the session-setup replies are still read as one PDU. A
  read of many long strings returned only the items in the first PDU (PLCSIM
  Advanced V8.0, CPU 1511, FW V2.9 sent 4 of 19 `String[254]` values) and left
  the rest in the stream, so the next request failed. A response is complete
  only when the `72 <ver> 00 00` trailer follows its data, a split stale
  response is drained before the awaited one is read, and the async client,
  like the sync one, rejects a final trailer of another protocol version. A
  notification split over several PDUs is still not reassembled; none has
  been observed (#91).
* A subscription built from a catalog tag (a `SymbolicTag`, or
  `SubscriptionItem.from_tag`) now sends SymbolCRC 0, as named reads and
  writes do. It sent the browsed per-entry CRC, which PLCSIM Advanced V8.0
  (CPU 1511, FW V2.9) answered with item error 0x13 and no values (#92).
* `get_cpu_state()` (both clients) reads the CPU's OperatingState code (member
  0xD9E of the struct attribute 0x8BD, struct id 0xD99: 8 = RUN, 4 = STOP)
  and no longer returns `"UNKNOWN"` for a running PLCSIM Advanced CPU. The
  4/8 values and the struct layout come from PLCSIM Advanced V8.0 (CPU 1511,
  FW V2.9) and TIA Portal captures only. A read-only probe of a real CPU 1215C
  (FW V4.2) has since read the same struct (id 0xD99) with code 8 in RUN;
  STOP (4) remains unverified on hardware. The cycle-load attributes it read
  before are now only a fallback when that code is absent. The server
  emulator reports its `cpu_state` the same way (#93).
* `AsyncClient` now derives the TLS OMS exporter secret the way `Client` does,
  so after a TLS 1.3 handshake `oms_secret` holds the secret that the new (AES)
  legitimation of S7-1500 firmware V3.1+ and S7-1200 V4.7+ encrypts with. It
  used to call an `export_keying_material` method that CPython's `ssl` does
  not have, so every TLS connect logged "Could not extract OMS exporter
  secret", `oms_secret` stayed `None` and `authenticate()` with the new
  exchange always raised `S7ConnectionError`. Together with the blob root id
  and PLCSIM device string fixes below, both clients now legitimate with the
  new exchange. Tested live on S7-PLCSIM Advanced V8.0 only (#94).
* On Windows, every TLS connection of the synchronous `Client` left a
  `s7-tls-keylog-*` file holding the session's TLS secrets in the temp
  directory. The handshake secrets are logged to that file to derive the OMS
  secret, and the SSL context kept it open, so it could not be deleted. Both
  clients now stop the key log before deleting the file, also when the
  handshake fails, and log a warning naming any key log they cannot delete.
  Files left behind by earlier versions hold old session secrets and can be
  deleted (#94).
* Password legitimation with the new (AES) exchange was refused on S7-PLCSIM
  Advanced V8.0 whatever the password: the encrypted credentials wrote their
  username and password Blobs without the blob root id that every Blob
  carries, so the PLC could not read them. With it, the correct password is
  accepted there. Real S7-1500 V3.1+ and S7-1200 V4.7+ build the same payload
  but are untested; the new exchange had not been validated on any PLC before
  (#95).
* TLS password legitimation now works on S7-PLCSIM Advanced. It reports itself as
  `1;6ES7 SIM-01500-APLC;S4.1` instead of the project's CPU, which the device
  string parser could not read, so `authenticate()` (and `connect(password=...)`)
  raised "PLC firmware version does not support legitimation". The parser now
  reads it as the reference driver's pattern does: an S7-1500 at version 4.1,
  which takes the new exchange. PLCSIM refuses the legacy exchange, even for a
  project whose CPU firmware (V2.9) would use it on hardware. Seen on PLCSIM
  Advanced V8.0 only. A device string with a newline or a minor version of more
  than four digits is now unreadable, so `authenticate()` refuses it like any
  other; a minor version of thousands of digits used to escape as a bare
  `ValueError` (#95).
* `parse_block_interface()` / `block_interface_from_explore()` now return the
  members of instance DBs and DBs declared of a UDT instead of an empty list
  (#118).
* `FamilyOnlyFingerprintError`, `UnknownPublicKeyError` and any other `S7Error`
  subclass whose constructor takes more than the message can now be pickled,
  copied and deep-copied, so they cross process boundaries intact (#111).
* On Windows, `S7CommPlusServer.start()` raises `OSError` when the port is
  already in use, instead of sharing it with the other listener (#113).
* A timeout no longer leaves a dead session behind that still reports
  `connected`. A request whose reply does not arrive within the request
  timeout (for an EXPLORE, the EXPLORE timeout), and any read that stops
  part-way through a frame or a multi-part reply (in the async client also
  one cancelled from outside), close the session without a DeleteSession
  exchange and raise `S7TimeoutError`. The session is then handled like one
  the PLC dropped: `connected` reports `False`, the next request raises
  `S7ConnectionError("Not connected")`, and the connect parameters and the
  subscription bookkeeping are kept. Before, the sync client marked only its
  socket dead, so `connected` stayed `True` while every later request failed
  with "Not connected", and an async wait that ended between a frame's header
  and its body left the stream out of step. A notification wait that runs out
  before any byte of the next frame arrived leaves the session usable, in the
  sync client too (#123).
* A failed reconnect inside `AsyncClient.browse()` no longer discards the
  `connect()` parameters, which made every later request fail with "Not
  connected" until `connect()` was called again (#122).

### Documentation

* `delete_subscription()` and `delete_alarm_subscription()` now say that they
  delete the session's whole subscription container, every data and alarm
  subscription of the session, not only the one named (#100).

### Testing

* The server emulator accepts `max_response_pdu`, which splits every response
  after session setup over several PDUs as a PLC does, authenticated V3
  responses included (#91).
* The server emulator accepts `max_request_bytes` and, like a PLC, closes the
  connection on a longer request frame, counted after TLS decryption as the
  clients count it (#100).
* The real-PLC acceptance suite gains Gherkin scenarios for browsing and named
  reads and writes, data and alarm subscriptions, the CPU operating state, TLS
  (an untrusted CA is refused) and password legitimation, plus `@pending`
  scenarios for `reconnect()` and certificate pinning from open pull requests.
  Every scenario runs with both `Client` and `AsyncClient` (`--client`). The
  password comes only from `S7COMMPLUS_TEST_PASSWORD` and is redacted from the
  reports. CI dry-runs every scenario against fake clients, so an unbound step
  or stale step code fails before a volunteer's PLC run does (#108).

### Thanks

* @sullibar for the PLCSIM Advanced validation and most of this release's
  features and fixes (#83, #91–#95, #97, #98, #100, #101, #103, #106, #107).
* @bvanelli for the preset-stream iterator, the EXPLORE ReturnValue check and
  the instance DB interface fix (#64, #110, #118).

0.2.0 (2026-10-08)
------------------

The V1 SessionKey handshake (V1-initial S7-1200/S7-1500 without TLS) no longer
runs transpiled HarpoS7 code. Every cryptographic step was identified, proven
equal to the original, and replaced with a small readable module. As a result,
authentication is roughly 300× faster, `AsyncClient` gains V1 SessionKey
support, and the package is renamed after what it does (#1, #44).

### Upgrading from 0.1.0

The SessionKey package and its helpers were renamed. There is no compatibility
shim, because 0.1.0 was an early prerelease. Most applications only use `Client`
and `AsyncClient` and need no changes.

| 0.1.0 | 0.2.0 |
| --- | --- |
| `s7commplus.session_auth` | `s7commplus.v1_session_key` |
| `session_auth.family0` | `v1_session_key.real_plc` |
| `session_auth.legacy_auth` | `v1_session_key.handshake` |
| `session_auth.legitimate` | `v1_session_key.legitimation` |
| `HarpoAes`, `.encrypt_ecb()` | `AesEcb`, `.encrypt()` |
| `HarpoAesCtr`, `.init()` / `.encrypt_ctr()` / `.calculate_checksum()` | `AesGcm24`, `.start()` / `.encrypt()` / `.tag()` |
| `harpo_hash.lut1`, `generate_lookup_table`, `hash_block`, `LUT_SEED` | `ghash.times_x`, `multiplication_table`, `multiply`, `REDUCTION_TABLE` |
| `generate_lookup_table`, `hash_block`, `lut1` re-exported from the package | the `ghash` module is exported instead |

Other behaviour changes:

* `AsyncClient.explore()` now reassembles multi-fragment responses, as
  `Client.explore()` already did.
* The wheel no longer ships the analyses of retired HarpoS7 code or the artifact
  manifest (`artifacts.json`). They moved to `old/family0/` in the repository.
  `fingerprint_gates.bin` is gone.
* A legitimation the PLC refuses because of the password now raises
  `S7AuthenticationError`, not `S7ConnectionError`. Other rejections still raise
  `S7ConnectionError` (#73).
* The dictionaries returned by `list_datablocks()` gain the keys `language`,
  `knowhow_protected` and `unlinked` (#77). Existing keys are unchanged.

### New features

* `AsyncClient` supports V1 SessionKey authentication: the SecurityKey setup,
  activation and V1 password legitimation; V3 HMAC framing and verification;
  same-family key fallback; SessionKey renewal; and the `legacy_s7_1500`
  profile. `AsyncClient.connect()` accepts the same options as `Client.connect()`
  (`password`, `allow_legacy_key_fallback`,
  `legacy_session_key_refresh_interval`, `legacy_s7_1500`). Before, it refused
  these PLCs (#44).
* Opt-in `legacy_s7_1500=True` profile for the non-TLS S7-1512SP on firmware 2.6:
  browse and symbolic reads (#35, #12).
* Complete data-subscription lifecycle in both clients: subscriptions from
  catalog tags, symbolic access strings or explicit items; typed and raw
  notifications; bounded queues, callbacks and sync/async iterators with
  overflow diagnostics; finite-credit replenishment; data and alarm routing;
  early-notification buffering and stale-ID protection. Subscriptions are
  released on disconnect (#36, #7).
* `Client.resubscribe()` and `AsyncClient.resubscribe()` recreate the data
  subscriptions the PLC released after a reconnect. The returned
  `SubscriptionRestoreResult` maps each old ID to its new one, reports
  subscriptions the PLC rejected in `failed` without stopping the others, and
  `forget_lost_subscriptions()` drops what is still pending. It is opt-in:
  nothing is recreated implicitly, notifications from the gap are not replayed
  and alarm subscriptions are not restored (#69, #67).
* `connect(..., connection_type="hmi" | "es" | "pg")` on both clients selects the
  COTP identity the client presents. The default `"hmi"` is what the library has
  always used; whether firmware treats `"es"` or `"pg"` differently is not
  verified against a PLC (#74).
* Session introspection on both clients: `secured_session` (the secured-session
  bit of `ServerSession.Role`), `server_session_roles` (the raw `Roles` mask) and
  `session_oms_version` (negotiated SystemOMS and ProjectOMS, logged as `V1` to
  `V7` at connect, with a warning when a controller reports ProjectOMS 0). The bit
  meanings are inferred from TIA Portal captures, not verified against a PLC
  (#76, #85, #80, #86).
* `device_name()`, `device_family()` and `DEVICE_NAMES` map a controller's order
  number to its module name and family for S7-1200/1500 CPUs, SIPLUS variants,
  software controllers and PLCSIM (#75).
* `attribute_name()` and `describe_attribute()` name attribute ids for the
  ServerSession, Block, CPUexecUnit, Subscription and AlarmSubsystem classes.
  Unknown ids degrade to a numeric description (#84).
* Protocol tables in `protocol.py`: `AttributeFlags` with
  `attribute_flags_description()` (#79), `BlockLanguage` with
  `block_language_name()` (#77), `ServiceResult` with `service_result_code()`
  (#73), `invoke_method_name()` for INVOKE calls (#78), the operating-state
  attribute ids and `OperatingStateRequest` values (#81), and further wire
  constants (#72). The sources of the values are TIA Portal captures unless stated,
  and the constants are not verified against a live PLC. No operating-state write
  path ships (#8).
* PLCSIM / PLCSIM Advanced (key family 03) V1 SessionKey authentication, with an
  ECIES-over-P-256 seed (#65, #56). Emulator-tested only; see the known
  limitations.
* `Ids` gains the data-interface and comment attribute ids (#60).

### Performance

* Full V1 SessionKey authentication takes about 1.3–1.6 ms instead of 446 ms,
  and the challenge fingerprint about 0.01 ms instead of 0.51 ms (#44).

### Readability and auditability (#1)

* The handshake's primitives are identified and implemented directly, in about
  600 lines in `v1_session_key/real_plc/`: SeedTransform is x-only ECDH on a
  160-bit prime-order curve over `GF(2^160 − 47)`; PreSeed, Transform13 and
  KeyDerivation are PRESENT-80; the blob checksum is a GF(2^128) multiply; and
  the challenge fingerprint is a white-boxed fixed-key SPN on AES's inverse
  S-box. HarpoHash and HarpoAesCtr are GHASH and AES-GCM with a 24-bit counter
  (#44).
* No generated code or binary tables ship at runtime. The transpiled HarpoS7
  originals are kept, unshipped, under `old/family0/` as the references the
  tests compare against (#44).
* Tools to regenerate and verify every retained artifact against the pinned
  HarpoS7 revision (#40), plus the analyses and proofs behind the migration
  (#41, #42, #44).

### Bug fixes and hardening

* Stop logging the SessionKey session challenge bytes (#44).
* A V1 SessionKey connect without a password no longer sends the post-auth
  legitimation. S7-1200 PLCs with key family 01 reject it but still serve reads,
  so the connect used to fail. A wrong password still raises
  `S7ConnectionError` (#70, #71).
* SetupSession replies now go through the response dispatcher: a fatal
  SystemEvent is reported instead of being mistaken for a successful setup, and
  the reply function and sequence number are validated (#39, #34).
* `explore()` sends the structured EXPLORE request (#59), and the named tag API
  sends SymbolCRC 0 (#58).
* The server emulator refuses items it cannot resolve and writes whose value is
  not the size their address names (#62).
* The real-PLC acceptance runner redacts the tester's hostname from JUnit
  reports (#38).

### Documentation

* PyPI is the documented installation path for stable users (#31).
* A maintainer map of the V1 SessionKey call path, with a failure-diagnosis
  guide (#37), and the observed firmware-to-session-path mapping (#57).
* Explain previously "unknown" protocol bytes from independent TIA Portal
  captures (#46), and document request-counter, notification-frame and
  diagnostic-subscription behaviour (#47).

### Testing

* Golden TIA Portal ↔ PLCSIM capture fixtures with pinned parser regression
  tests (#48).
* CI runs the oldest and newest Linux, macOS and Windows runners (#63).
* Tests that study retired HarpoS7 code are marked `analysis` and run with
  `pytest --analysis`. CI passes the flag; a plain `pytest` takes about a
  minute (#44).

### Known limitations

* The rewritten cryptography is verified against HarpoS7's vectors, captured
  TIA traffic and the emulator, and was confirmed on an S7-1200 1215C (FW V4.2)
  with both the sync and async clients (#44). A V1 S7-1500 retest of the new
  code is still pending.
* PLCSIM's legacy authentication (key family 03) is implemented (#56) but only
  tested against the emulator. It skips the post-auth legitimation and rejects a
  `password` until a real PLCSIM capture shows what PLCSIM expects (#66).

### Thanks

* @AndrewStuhr for validating the S7-1512SP firmware 2.6 profile on hardware
  (#12, #35).
* @bmappi for the independent TIA Portal capture analysis behind #46–#48 (#45).
* @russwing for S7-1200 and S7-1500 TLS hardware reports (#32, #33).
* @xBiggs for the V1-initial S7-1200 SessionKey hardware testing this code is
  built on.
* @bonk-dev for [HarpoS7](https://github.com/bonk-dev/HarpoS7), which made the
  SessionKey handshake possible.

0.1.0
-----

First release as a standalone package, split out of python-snap7. See the
[v0.1.0 release notes](https://github.com/gijzelaerr/s7commplus/releases/tag/v0.1.0).
