# CLAUDE.md

This file provides guidance to Claude Code and other AI coding assistants when
working in this repository.

## Project overview

`s7commplus` is a standalone, pure-Python implementation of the S7CommPlus
protocol used by Siemens S7-1200 and S7-1500 PLCs. It was split out of
`python-snap7`; this repository does **not** contain the classic S7 protocol or
the `snap7` package. Use `python-snap7` for S7-300/400 communication and classic
PUT/GET access.

The package supports Python 3.10 and newer, S7CommPlus V1, V2 with TLS, and V3,
with synchronous and asyncio clients plus a server emulator for tests. It has no
native runtime dependency; `cryptography` is its only runtime dependency.

This is an unofficial implementation. Changes involving a real PLC must be
tested against an isolated, non-safety-critical controller.

## Repository layout

- `s7commplus/client.py`: synchronous high-level client and request builders
- `s7commplus/async_client.py`: asyncio client; keep behavior aligned with the
  synchronous client when changing shared operations
- `s7commplus/connection.py`: synchronous session lifecycle, TLS-in-COTP,
  authentication, request sequencing, and V3 integrity protection
- `s7commplus/transport.py`: TCP, TPKT, and COTP transport
- `s7commplus/protocol.py`: protocol constants and enums; excluded from
  pre-commit because its formatting is intentionally preserved
- `s7commplus/codec.py` and `s7commplus/vlq.py`: wire-format encoding and decoding
- `s7commplus/server.py`: S7CommPlus server emulator and in-memory data blocks
- `s7commplus/tag_browser.py`, `typeinfo.py`, and `blob_decompressor.py`: symbol,
  type-information, and compressed metadata parsing
- `s7commplus/subscription.py` and `alarm.py`: cyclic subscriptions and alarms
- `s7commplus/legitimation.py`: client-side password legitimation flow
- `s7commplus/session_auth/`: session authentication and HarpoS7-derived
  cryptographic algorithms
- `s7commplus/session_auth/family0/_generated/`: generated translations of
  authentication transforms; avoid hand-editing without a specific reason
- `s7commplus/zlib_dicts/`: preset dictionaries used to decompress PLC metadata
- `tests/`: unit, protocol conformance, emulator, TLS, authentication, and
  opt-in real-PLC tests

Package data matters: `py.typed`, authentication `.bin` files, and zlib
dictionary `.xml` files are included through `pyproject.toml`. Do not move,
rename, or omit them from distributions accidentally.

The session-authentication code derives from HarpoS7. Preserve its attribution
and `s7commplus/session_auth/LICENSE-HarpoS7` when changing or redistributing it.

## Protocol stack and design constraints

The on-wire stack is TCP -> RFC 1006 TPKT -> COTP -> S7CommPlus. For TLS
sessions, TLS records are carried inside COTP data frames; TPKT/COTP headers are
not part of the encrypted stream. Do not replace this with an ordinary TLS
socket without accounting for that framing.

Protocol parsing must treat PLC data as untrusted:

- Validate lengths, offsets, sequence numbers, function codes, and return values.
- Use the explicit big-endian encoders/decoders and VLQ helpers already present.
- Raise exceptions from `s7commplus.error` for connection, protocol,
  authentication, timeout, and sequencing failures.
- Avoid logging passwords, session keys, challenges, private keys, or decrypted
  authentication material.
- Preserve compatibility across V1, V2, and V3 paths. A fix for one negotiated
  version must not silently change another.
- Keep sync and async behavior, validation, and public method signatures in
  parity unless the difference is inherently transport-specific.

Prefer extending existing codec and payload helpers over duplicating byte-level
logic. Keep socket/session mechanics in `connection.py` or `transport.py`, wire
encoding in codecs/builders, and user-facing operations in the clients.

## Public API

The main imports are `Client`, `AsyncClient`, and `Server` from `s7commplus`.
The package also exports subscription, alarm, tag-browser, data-block, and
decompression types and helpers from `s7commplus/__init__.py`. Update
`__all__` deliberately when adding public API.

```python
from s7commplus import Client

with Client() as client:
    client.connect("192.168.1.10", port=102)
    data = client.db_read(1, 0, 4)
    client.db_write(1, 0, b"\x01\x02\x03\x04")
```

```python
from s7commplus import AsyncClient

async with AsyncClient() as client:
    await client.connect("192.168.1.10", port=102)
    data = await client.db_read(1, 0, 4)
```

TLS connections use the `use_tls`, `tls_cert`, `tls_key`, and `tls_ca`
arguments to `connect()`. The synchronous client also accepts `password` there;
with the async client, call `authenticate()` after connecting. Never weaken
certificate verification or authentication defaults merely to make an
integration test pass.

## Development setup and checks

Install the project and development tools:

```bash
python -m pip install -e '.[test]'
```

Run the complete local check before every commit:

```bash
pytest
mypy s7commplus
ruff check s7commplus tests
ruff format --check s7commplus tests
pre-commit run --all-files
```

Useful focused commands:

```bash
pytest tests/test_s7_unit.py
pytest tests/test_s7_tls.py
pytest tests/test_session_auth.py
pytest -m conformance
```

Ruff targets Python 3.10 and uses a 130-character line length. MyPy runs in
strict mode. The normal test suite uses local emulators and fixtures and must
not require PLC or network access.

Real-PLC tests are marked `e2e`, skipped by default, and must be explicitly
enabled:

```bash
pytest --e2e --plc-ip 192.168.1.10 --plc-port 102 \
  --plc-rack 0 --plc-slot 1 --plc-db-read 1 --plc-db-write 2
```

The write DB supplied to E2E tests must be disposable and safe to modify. Never
run E2E tests against an unknown, production, or safety-related PLC. Do not turn
an E2E failure into a unit-test skip; reproduce protocol behavior with the
server emulator or captured byte fixtures when possible.

## Testing expectations

- Add byte-exact tests for new encoders, decoders, request layouts, and protocol
  version branches.
- Add malformed and truncated input cases for parsers.
- Exercise both sync and async clients when shared user-visible behavior changes.
- Use `S7CommPlusServer` for end-to-end client/server behavior that does not
  require actual firmware.
- Keep binary fixtures immutable unless intentionally replacing their known
  source/expected pair; do not reformat or normalize `.bin` data.
- Tests of authentication transformations should retain known-answer vectors.
- Bug fixes should include a regression test that fails without the fix.

## Code quality and contribution rules

- Use logging rather than `print()` for library diagnostics.
- Keep public functions and methods typed; MyPy strict mode must remain clean.
- Prefer small, focused changes and one coherent purpose per pull request.
- Do not add `snap7` compatibility shims or restore legacy S7 modules here; the
  package boundary is intentional.
- Do not make unrelated changes to generated authentication code, binary
  fixtures, or preset dictionaries.
- Run `pre-commit run --all-files` before every push; it covers repository checks
  beyond standalone Ruff and MyPy invocations.
- Update `README.md`, package exports, metadata, and tests when a public API or
  supported-version claim changes.
