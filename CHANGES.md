CHANGES
=======

0.3.0 (unreleased)
------------------

### New features

* `iter_preset_streams()` yields each preset-dictionary zlib stream in an EXPLORE
  payload as a `PresetStream`, in the order the streams appear, and skips streams
  that are empty or fail to decompress (#64). `iter_preset_headers()` yields the
  offset and `PresetIdentity` of each stream without decompressing it.
  `PresetIdentity` names a preset dictionary by `adler`, `kind` and
  `version`, parsed from its file name. `zlib_dicts.ZLIB_DICT_IDENTITIES`
  maps each Adler-32 to one and supersedes `ZLIB_DICT_NAMES`, which is kept
  for compatibility (#64).
* `read_tags`, `read_symbolic_multi`, `db_read_multi`, `db_write_multi` and
  `write_tags` (both clients) split a large batch over several requests of at
  most `max_items_per_request` items (default 50; `0` sends a batch in one
  request) and return the results in item order. A CPU 1215C FW V4.2 (non-TLS
  V1 SessionKey session) answers a read of 50 items and refuses one of 51 or
  more with return value `0xA027A6000054FFFC`, whatever the request size;
  PLCSIM Advanced V8 (CPU 1511) is limited by the request size instead, and
  S7-1500 hardware has not been measured.
* The same methods keep each request frame within `max_request_bytes` (default
  900; `0` disables the check), counted from the S7CommPlus frame header to its
  trailer with the IntegrityId at its 5-byte maximum and any SessionKey HMAC,
  but without the TLS record, COTP and TPKT. On PLCSIM Advanced V8 (CPU 1511,
  FW V2.9, TLS project) a read with a 1034-byte payload (a frame of about 1060
  bytes) made the PLC drop the connection, and one with an 834-byte payload was
  answered; real hardware has not been measured.
* `create_subscriptions()` (both clients) spreads items over as many
  subscriptions as `max_request_bytes` requires, in order, and returns their
  IDs; reference IDs stay unique across them. If a subscription after the first
  fails, it raises the new `s7commplus.error.S7SubscriptionError`, whose
  `created` lists the subscriptions already created; they stay active.
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
  S7CommPlus dissector, at an unverified line.
* Setting `auto_refresh_tags = True` (both clients, opt-in) runs that check when
  a tag read reports a failed item or a name is unknown and, if the program
  changed, resolves and reads the names again, once. It checks at most once per
  call and once every 10 seconds, so a tag that keeps failing or a misspelt name
  does not add 1 + N requests to every poll. A write that reached the PLC is
  never resent, and a write to a stale address does not trigger the check.
* Typed values: `read_value()`, `read_values()`, `write_value()` and
  `write_values()` (both clients) read and write Python values by tag name
  instead of raw bytes, for every elementary type including strings, dates and
  times. The name of a struct, UDT, DTL or array reads or writes all its leaves
  as one batch, as a `dict`, `list` or `datetime`. A value the PLC type cannot
  hold raises `TypeError` or `ValueError` naming the leaf before anything is
  sent. With `auto_refresh_tags` set, a name not in the catalog runs the
  rate-limited program-change check once and is looked up again, as in
  `read_tags`. Validated against PLCSIM Advanced (V8.0, CPU 1511, FW V2.9) for
  every type in the test project; not yet checked on hardware.
* The new `s7commplus.values` module converts raw tag values to Python values
  and back (`decode()`, `encode()`; `SymbolicTag.encode_value()` is new) and
  builds structs and arrays from their leaves (`assemble()`, `split()`).
  Date and time values are naive: no PLC date or time type stores a time zone,
  so an aware `datetime` or `time` raises `ValueError` instead of being shifted
  or stripped. Ranges follow the TIA Portal data type documentation (DATE to
  2168-12-31, LDT and DTL 1970-01-01 to 2262-04-11). A STRING or WSTRING is
  encoded with its declared length (`string_length`), which sets its header and
  padding; when the catalog does not give it (`0`), encoding raises `ValueError`
  instead of assuming 254. `SymbolCatalog.members()` lists the leaf tags of a
  struct, UDT, DTL or array.

### Behaviour changes

* `tags_from_explore()` and `block_interface_from_explore()` select their stream
  by dictionary kind instead of a hard-coded Adler-32, so a new version of a
  dictionary, once added to the package, is picked up without code changes.
  The streams picked for the bundled dictionaries are unchanged (#64).
* Multi-item reads and writes (`read_tags`, `read_symbolic_multi`,
  `db_read_multi`, `db_write_multi`, `write_tags`, both clients) are split into
  requests of at most 50 items and 900 bytes. A batch that used to go out in
  one request may now take several; set `max_items_per_request` or
  `max_request_bytes` to `0` to turn either bound off.
* A `db_write_multi` or `write_tags` batch split over several requests is not
  atomic. The requests go out in order and a refused item does not stop the
  batch; `db_write_multi` then raises the new `s7commplus.error.S7WriteError`
  after the last request, with `item_errors` keyed by position in the whole
  batch. A connection, timeout or protocol failure after the first request
  stops the batch: `db_write_multi` raises `S7WriteError` from it, and
  `write_tags` returns its results with that error on every tag it could not
  confirm; `unknown` and `not_sent` name the items that may or may not have been
  written and the ones never sent. A failure of the first request propagates
  unchanged. Upgrade note: `S7WriteError` is a `RuntimeError`, so existing
  handlers still catch refused writes; keep a batch to one request if it must
  not be applied in part.
* `db_read_multi` returns `b""` for each item of a request the PLC refuses as a
  whole, where it returned a shorter list, and raises `RuntimeError` when an
  answer skips or repeats an item, so no value can land on another item. The
  multi-item methods send no request for an empty batch.
* An item too large for one request on its own (for example a `db_write` of a
  long byte block, or a long string in `write_tags`) raises `ValueError` before
  anything is sent, where the request used to go out and the PLC dropped the
  connection. Upgrade note: set `max_request_bytes` higher, or to `0`, for a
  PLC that accepts larger requests.
* `create_subscription()` raises `ValueError` instead of sending a request over
  `max_request_bytes`, which the PLC would answer by dropping the connection; at
  the default that is about 40 to 46 items with a one-level LID path. Upgrade
  note: call `create_subscriptions()` for more items, or set
  `max_request_bytes = 0` to send the request anyway.
* `SymbolicTag.decode_value()`, and with it subscription `decoded_values`, now
  decodes STRING and WSTRING by their length header (it used to decode the
  header bytes as text), CHAR, WCHAR, the date and time types, and array
  elements, which it used to leave as bytes. Bytes that are not a valid value
  of the type, or lie outside its range, are still returned unchanged.

### Bug fixes and hardening

* Every data response the PLC splits over several PDUs is now reassembled,
  not only Explore; the session-setup replies are still read as one PDU. A
  read of many long strings returned only the items in the first PDU (PLCSIM
  Advanced V8.0, CPU 1511, FW V2.9 sent 4 of 19 `String[254]` values) and left
  the rest in the stream, so the next request failed. A response is complete
  only when the `72 <ver> 00 00` trailer follows its data, a split stale
  response is drained before the awaited one is read, and the async client,
  like the sync one, rejects a final trailer of another protocol version. A
  notification split over several PDUs is still not reassembled; none has
  been observed.
* `write_tags()` sends CHAR as a USINT, STRING and WSTRING as USINT and UINT
  arrays of `[max length, length, characters]` padded to the declared length,
  and DATE_AND_TIME as an array of its eight BCD bytes. PLCSIM Advanced (V8.0,
  CPU 1511, FW V2.9 with TLS and FW V2.8 without) rejected every named write of
  these types in the previous forms and accepts the new ones. The new forms are
  verified on PLCSIM only, not on a hardware PLC. The new `legacy_write_forms`
  attribute (both clients, default `False`) sends the previous forms instead:
  CHAR as BYTE, STRING as S7STRING, WSTRING as WSTRING and DATE_AND_TIME as
  TIMESTAMP, each value's bytes as given. That is the 0.2.0 behaviour; it was
  not checked on a hardware PLC either. **Upgrade note:** by default,
  `write_tags()` and `write_tag()` now take a STRING or WSTRING value only in
  the layout a read returns, `[max length, length, characters]` padded with
  zeros to the declared length (a WSTRING as big-endian UINTs), and send it as
  that array; bytes in another form, such as the characters alone, are no
  longer wrapped in a string PValue. Set `legacy_write_forms = True` to keep
  the 0.2.0 forms. DATE_AND_TIME data is still its eight BCD bytes.

### Documentation

* `delete_subscription()` and `delete_alarm_subscription()` now say that they
  delete the session's whole subscription container, every data and alarm
  subscription of the session, not only the one named.

### Testing

* The server emulator accepts `max_response_pdu`, which splits every response
  after session setup over several PDUs as a PLC does, authenticated V3
  responses included.
* The server emulator accepts `max_request_bytes` and, like a PLC, closes the
  connection on a longer request frame, counted after TLS decryption as the
  clients count it.

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
