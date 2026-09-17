# s7commplus

Pure-Python S7CommPlus communication for Siemens S7-1200 and S7-1500 PLCs.
It supports S7CommPlus V1, V2 (TLS), and V3; synchronous and asyncio clients;
and a server emulator for testing.

```bash
pip install s7commplus
```

```python
from s7commplus import Client

with Client() as client:
    client.connect("192.168.1.10", 0, 1)
    data = client.db_read(1, 0, 4)
```

S7CommPlus is used by newer S7-1200/1500 PLCs when classic PUT/GET access is
disabled. This is an unofficial implementation and is not affiliated with,
endorsed by, or supported by Siemens AG. Test against an isolated controller
before using it in production or safety-relevant environments.

Some older PLCs advertise only their SessionKey family instead of a complete
public-key fingerprint. The synchronous `Client` tries the bounded set of
bundled keys from that family on fresh sessions and caches the confirmed key
for the PLC. Set `allow_legacy_key_fallback=False` on `connect()` when key
probing must be disabled.

## Development

```bash
python -m pip install -e '.[test]'
pytest
ruff check s7commplus tests
ruff format --check s7commplus tests
```

The session-authentication implementation derives from HarpoS7; its MIT
license is included at `s7commplus/session_auth/LICENSE-HarpoS7`.
