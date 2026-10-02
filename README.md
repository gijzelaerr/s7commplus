# s7commplus

Pure-Python S7CommPlus communication for Siemens S7-1200 and S7-1500 PLCs.
It supports S7CommPlus V1, V2 (TLS), and V3; synchronous and asyncio clients;
and a server emulator for testing. Both clients support legacy V1 SessionKey
authentication; the synchronous client's implementation is the one validated
on real controllers, while the asyncio client's is so far emulator-tested.

## Installation

Install the latest stable release from
[PyPI](https://pypi.org/project/s7commplus/):

```bash
python -m pip install --upgrade s7commplus
```

See the [s7commplus documentation](https://s7commplus.readthedocs.io/) for the
complete user guide and API reference.

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
public-key fingerprint. `Client` and `AsyncClient` try the bounded set of
bundled keys from that family on fresh sessions and cache the confirmed key
for the PLC. Set `allow_legacy_key_fallback=False` on `connect()` when key
probing must be disabled.

## Development

Cloning the repository is only necessary for developing or testing
`s7commplus`. To use the stable library in an application, install it from PyPI
as shown above.

```bash
git clone https://github.com/gijzelaerr/s7commplus.git
cd s7commplus
python -m pip install -e '.[test,docs]'
pytest
mypy s7commplus
ruff check s7commplus tests
ruff format --check s7commplus tests
```

The published documentation is hosted on
[Read the Docs](https://s7commplus.readthedocs.io/) and validated in CI. To
build it locally from a development checkout:

```bash
sphinx-build -W --keep-going -b html docs docs/_build/html
```

The V1 SessionKey implementation derives from HarpoS7; its MIT
license is included at `s7commplus/v1_session_key/LICENSE-HarpoS7`.
