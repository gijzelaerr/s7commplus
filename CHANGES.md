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

### Behaviour changes

* `tags_from_explore()` and `block_interface_from_explore()` select their stream
  by dictionary kind instead of a hard-coded Adler-32, so a new version of a
  dictionary, once added to the package, is picked up without code changes.
  The streams picked for the bundled dictionaries are unchanged (#64).

### Bug fixes and hardening

* `AsyncClient` now derives the TLS OMS exporter secret the way `Client` does,
  so after a TLS 1.3 handshake `oms_secret` holds the secret that the new (AES)
  legitimation of S7-1500 firmware V3.1+ and S7-1200 V4.7+ encrypts with. It
  used to call an `export_keying_material` method that CPython's `ssl` does
  not have, so every TLS connect logged "Could not extract OMS exporter
  secret", `oms_secret` stayed `None` and `authenticate()` with the new
  exchange always raised `S7ConnectionError`. The new exchange also needs the
  blob root id fix in its payload, which was refused whatever the password,
  and on PLCSIM the device string fix. Tested live on S7-PLCSIM Advanced V8.0
  only: both clients derive the secret, and with those fixes both legitimate.
* On Windows, every TLS connection of the synchronous `Client` left a
  `s7-tls-keylog-*` file holding the session's TLS secrets in the temp
  directory. The handshake secrets are logged to that file to derive the OMS
  secret, and the SSL context kept it open, so it could not be deleted. Both
  clients now stop the key log before deleting the file, also when the
  handshake fails, and log a warning naming any key log they cannot delete.
  Files left behind by earlier versions hold old session secrets and can be
  deleted.

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
