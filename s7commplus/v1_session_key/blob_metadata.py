"""SecurityKeyEncryptedKey blob metadata writer.

Produces the leading 48 bytes (12 little-endian uint32 dwords) of the
180-byte blob TIA Portal sends as the ``SessionKey`` value in its
session-setup write. ``real_plc.authenticator`` writes the remaining 132
bytes: the 60-byte seed field, the 16-byte counter IV, the encrypted
challenge and key2 (40 bytes), and the encrypted 16-byte checksum.

Layout (matches Wireshark s7comm-plus dissector field names):

  | offset | size | field                          |
  |--------|------|--------------------------------|
  | 0      | u32  | magic = 0xFEE1DEAD             |
  | 4      | u32  | blob length                    |
  | 8      | u32  | unknown1 (always 1)            |
  | 12     | u32  | unknown2 (always 1)            |
  | 16     | 8 B  | symmetric_key_checksum         |
  | 24     | u32  | symmetric_key_flags            |
  | 28     | u32  | symmetric_key_flags_internal   |
  | 32     | 8 B  | public_key_checksum            |
  | 40     | u32  | public_key_flags               |
  | 44     | u32  | public_key_flags_internal      |

Ported from HarpoS7 (MIT) — ``HarpoS7.Utilities.Auth.BlobMetadataWriter``.
"""

from __future__ import annotations

import struct

from .keys import (
    KeyFamily,
    PUBLIC_KEY_LENGTH_PLCSIM,
    PUBLIC_KEY_LENGTH_REAL_PLC,
)
from .utils import KEY_ID_LENGTH, derive_key_id

#: Length of the encrypted blob, in bytes, for real S7-1200/1500 PLCs.
ENCRYPTED_BLOB_LENGTH_REAL_PLC = 180

#: Length of the encrypted blob, in bytes, for PlcSim.
ENCRYPTED_BLOB_LENGTH_PLCSIM = 216

_BLOB_MAGIC = 0xFEE1DEAD
_METADATA_LENGTH = 48

_PUBLIC_KEY_LENGTH_BY_FAMILY: dict[KeyFamily, int] = {
    KeyFamily.S7_1500: PUBLIC_KEY_LENGTH_REAL_PLC,
    KeyFamily.S7_1200: PUBLIC_KEY_LENGTH_REAL_PLC,
    KeyFamily.PLCSIM: PUBLIC_KEY_LENGTH_PLCSIM,
}

_BLOB_LENGTH_BY_FAMILY: dict[KeyFamily, int] = {
    KeyFamily.S7_1500: ENCRYPTED_BLOB_LENGTH_REAL_PLC,
    KeyFamily.S7_1200: ENCRYPTED_BLOB_LENGTH_REAL_PLC,
    KeyFamily.PLCSIM: ENCRYPTED_BLOB_LENGTH_PLCSIM,
}

# Per-family flag constants observed in the wire format. Values come
# straight from HarpoS7.Utilities.Auth.BlobMetadataWriter.
_SYMMETRIC_KEY_FLAGS_BY_FAMILY: dict[KeyFamily, int] = {
    KeyFamily.S7_1500: 0x001,
    KeyFamily.S7_1200: 0x101,
    KeyFamily.PLCSIM: 0x301,
}

_PUBLIC_KEY_FLAGS_BY_FAMILY: dict[KeyFamily, int] = {
    KeyFamily.S7_1500: 0x010,
    KeyFamily.S7_1200: 0x110,
    KeyFamily.PLCSIM: 0x310,
}


#: Length of the encrypted seed field inside the blobs.
_ENCRYPTED_SEED_LENGTH_BY_FAMILY: dict[KeyFamily, int] = {
    KeyFamily.S7_1500: 60,
    KeyFamily.S7_1200: 60,
    KeyFamily.PLCSIM: 96,
}


def get_blob_length(family: KeyFamily) -> int:
    """Length of the full SecurityKeyEncryptedKey blob for a family."""
    return _BLOB_LENGTH_BY_FAMILY[family]


def get_encrypted_seed_length(family: KeyFamily) -> int:
    """Length of the encrypted seed field for a family (60 real PLCs, 96 PlcSim)."""
    return _ENCRYPTED_SEED_LENGTH_BY_FAMILY[family]


def get_symmetric_key_flags(family: KeyFamily) -> int:
    """``symmetric_key_flags`` field value for a family."""
    return _SYMMETRIC_KEY_FLAGS_BY_FAMILY[family]


def get_symmetric_key_flags_legitimation(family: KeyFamily) -> int:
    """``symmetric_key_flags`` used by the legitimation blob for a family.

    HarpoS7 writes a constant ``1`` for the real PLCs and the CSI session-key
    flags for PlcSim.
    """
    if family in (KeyFamily.S7_1500, KeyFamily.S7_1200):
        return 0x1
    return _SYMMETRIC_KEY_FLAGS_BY_FAMILY[family]


def get_public_key_flags(family: KeyFamily) -> int:
    """``public_key_flags`` field value for a family."""
    return _PUBLIC_KEY_FLAGS_BY_FAMILY[family]


def write_metadata(
    blob: bytearray | memoryview,
    public_key: bytes,
    symmetric_key: bytes,
    family: KeyFamily,
) -> int:
    """Write the 48-byte metadata header at the start of ``blob``.

    Args:
        blob: Mutable buffer; must be at least 48 bytes long.
        public_key: PLC public key bytes (40 for real PLCs, 64 for
            PlcSim). Only the leading 24 bytes are used by
            ``derive_key_id``; the rest is unused here.
        symmetric_key: 24-byte symmetric session key the client
            generated. Same caveat: only the first 24 bytes are used
            for the checksum.
        family: Public-key family from the PLC's CreateObject response.

    Returns:
        Next writable offset in the blob (always 48).

    Raises:
        ValueError: If buffers are too short or the family is invalid.
    """
    if len(blob) < _METADATA_LENGTH:
        raise ValueError(f"blob must be at least {_METADATA_LENGTH} bytes, got {len(blob)}")

    expected_pubkey_length = _PUBLIC_KEY_LENGTH_BY_FAMILY.get(family)
    if expected_pubkey_length is None:
        raise ValueError(f"Unsupported public-key family: {family!r}")
    if len(public_key) < expected_pubkey_length:
        raise ValueError(
            f"public_key must be at least {expected_pubkey_length} bytes for family {family.name}, got {len(public_key)}"
        )

    blob_length = _BLOB_LENGTH_BY_FAMILY[family]
    symmetric_flags = _SYMMETRIC_KEY_FLAGS_BY_FAMILY[family]
    public_flags = _PUBLIC_KEY_FLAGS_BY_FAMILY[family]

    struct.pack_into(
        "<IIII",
        blob,
        0,
        _BLOB_MAGIC,
        blob_length,
        1,  # unknown1 — observed always 1
        1,  # unknown2 — observed always 1
    )
    blob[16 : 16 + KEY_ID_LENGTH] = derive_key_id(symmetric_key)
    struct.pack_into("<II", blob, 24, symmetric_flags, 0)
    blob[32 : 32 + KEY_ID_LENGTH] = derive_key_id(public_key)
    struct.pack_into("<II", blob, 40, public_flags, 0)

    return _METADATA_LENGTH
