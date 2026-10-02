"""The S7CommPlus V1 SessionKey handshake.

Only S7CommPlus V1 sessions without TLS use this package: the ``SessionKey``
blob that V1-initial firmware requires, and the password legitimation that
follows it. V2 (TLS) and V3 sessions never use it; their password
legitimation is ``s7commplus.legitimation`` and their integrity handling is
in ``s7commplus.connection``.

This subpackage is a Python port of the legacy-challenge half of
`bonk-dev/HarpoS7 <https://github.com/bonk-dev/HarpoS7>`_ (MIT-licensed),
which itself is a clean-room re-implementation of the proprietary
authentication algorithm in Siemens' ``OMSp_core_managed.dll``.

The legacy-challenge handshake is what V1-initial S7-1200 firmware
(and pre-V17 TIA Portal) require for full S7CommPlus operation —
without it, ``browse()`` and other CommPlus data ops fail.

The package contains the public-key store, AES/SHA primitives, the blob
algorithm for real PLCs (``real_plc``), and the orchestration for the
180-byte ``SecurityKeyEncryptedKey`` blob (``handshake``, ``legitimation``). Family 03 keys/metadata are catalogued,
but its separate PLCSIM authentication implementation is not provided.
See ``MAINTAINER_GUIDE.md`` for stable boundaries and verification commands.

References:

- HarpoS7: https://github.com/bonk-dev/HarpoS7 (MIT)
- Cheng Lei et al. "The spear to break the security wall of S7CommPlus",
  Black Hat EU 2017.
- Biham, Bitan et al. "Rogue7", Black Hat USA 2019.
"""

from .blob_metadata import (
    ENCRYPTED_BLOB_LENGTH_PLCSIM,
    ENCRYPTED_BLOB_LENGTH_REAL_PLC,
    get_blob_length,
    get_public_key_flags,
    get_symmetric_key_flags,
    write_metadata,
)
from .key_derivation import (
    derive_challenge_encryption_key,
    derive_legitimation_challenge_key,
    derive_seed_encryption_key_and_iv,
)
from .aes_ecb import AES_BLOCK_SIZE, AES_KEY_LENGTH, AesEcb
from .aes_gcm import AesGcm24
from . import ghash
from .keys import (
    KeyFamily,
    PUBLIC_KEY_LENGTH_REAL_PLC,
    PUBLIC_KEY_LENGTH_PLCSIM,
    UnknownPublicKeyError,
    fingerprints_for_family,
    get_public_key,
    parse_family_identifier,
    parse_fingerprint,
)
from .utils import KEY_ID_LENGTH, derive_key_id

__all__ = [
    "AES_BLOCK_SIZE",
    "AES_KEY_LENGTH",
    "ENCRYPTED_BLOB_LENGTH_PLCSIM",
    "ENCRYPTED_BLOB_LENGTH_REAL_PLC",
    "AesEcb",
    "AesGcm24",
    "KeyFamily",
    "KEY_ID_LENGTH",
    "PUBLIC_KEY_LENGTH_REAL_PLC",
    "PUBLIC_KEY_LENGTH_PLCSIM",
    "UnknownPublicKeyError",
    "derive_challenge_encryption_key",
    "derive_key_id",
    "derive_legitimation_challenge_key",
    "derive_seed_encryption_key_and_iv",
    "fingerprints_for_family",
    "get_blob_length",
    "get_public_key",
    "get_public_key_flags",
    "get_symmetric_key_flags",
    "ghash",
    "parse_family_identifier",
    "parse_fingerprint",
    "write_metadata",
]
