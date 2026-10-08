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
  most `max_items_per_request` items (default 100; `0` sends a batch in one
  request) and return the results in item order. The default is not a measured
  PLC limit: PLCSIM Advanced V8 (CPU 1511, FW V2.9) answered reads of up to 80
  items, and no hardware limit has been checked.
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

### Behaviour changes

* `tags_from_explore()` and `block_interface_from_explore()` select their stream
  by dictionary kind instead of a hard-coded Adler-32, so a new version of a
  dictionary, once added to the package, is picked up without code changes.
  The streams picked for the bundled dictionaries are unchanged (#64).
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
