"""S7CommPlus zlib preset dictionaries for compressed blob decompression.

Extracted from thomas-v2/S7CommPlusDriver (LGPL-3.0):
  src/S7CommPlusDriver/Core/BlobDecompressor.cs

S7-1200/1500 PLCs compress various XML blobs (interface descriptions,
tag tables, line comments, debug info, etc.) using zlib with a preset
dictionary. Python's zlib.decompress() returns Z_NEED_DICT; we provide
the matching dictionary based on the Adler-32 checksum in the zlib header.

Each dictionary is stored as a readable ``.xml`` file in this package
directory, named ``{adler32}_{name}.xml``. They are loaded once at
import time and indexed by Adler-32 checksum.

`ZLIB_DICT_IDENTITIES` is the structured view of each file name (kind and
version). `ZLIB_DICT_NAMES` holds the same information as a flat display
string and is kept for compatibility; prefer `ZLIB_DICT_IDENTITIES` in new code.
"""

from dataclasses import dataclass
from pathlib import Path as _Path


@dataclass(frozen=True)
class PresetIdentity:
    """Identity of a Siemens zlib preset dictionary.

    Attributes:
        adler: Adler-32 of the dictionary, as carried in the zlib header DICTID.
        kind: Dictionary family without its version, e.g. `DebugInfo IntfDesc` or `LineComm`.
        version: Dictionary version, e.g. `0x98000001`.
    """

    adler: int
    kind: str
    version: int


_DIR = _Path(__file__).parent

ZLIB_DICT_IDENTITIES: dict[int, PresetIdentity] = {}
ZLIB_DICT_NAMES: dict[int, str] = {}
ZLIB_DICTIONARIES: dict[int, bytes] = {}

for _f in sorted(_DIR.glob("*.xml")):
    try:
        _adler_hex, _rest = _f.stem.split("_", 1)
        _adler = int(_adler_hex, 16)
        _kind, _version_hex = _rest.rsplit("_", 1)
        _version = int(_version_hex, 16)
    except ValueError as _e:
        raise ImportError(f"Preset dictionary {_f.name!r} is not named {{adler32}}_{{kind}}_{{version}}.xml") from _e
    if _adler in ZLIB_DICT_IDENTITIES:
        raise ImportError(f"Preset dictionary {_f.name!r} repeats Adler-32 0x{_adler:08x}")
    ZLIB_DICT_IDENTITIES[_adler] = PresetIdentity(_adler, _kind.replace("_", " "), _version)
    ZLIB_DICT_NAMES[_adler] = _rest.replace("_", " ")
    ZLIB_DICTIONARIES[_adler] = _f.read_bytes().rstrip(b"\n")
