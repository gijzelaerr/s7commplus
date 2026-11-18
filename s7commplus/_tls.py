"""TLS inside COTP: the context, certificate pinning and the OMS secret, without I/O.

S7CommPlus carries TLS records as the payload of COTP data frames, so both
clients drive an ``ssl.SSLObject`` over memory BIOs instead of wrapping the
socket. These helpers moved here from the connection module, which
re-exports them.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import ssl
import tempfile
from collections.abc import Iterator
from typing import Any, Optional

from .error import S7CertificateError

# Logged under the connection module's name, as before the move.
logger = logging.getLogger("s7commplus.connection")


# TLS cipher suites for S7 PLC compatibility.
# ECDHE suites are preferred (forward secrecy); RSA-kx kept as fallback for
# older firmware.  The key to Siemens PLC compatibility is restricting the
# offered groups to x25519 via set_ecdh_curve — PLCs RST when they see
# unsupported groups like x448 or ffdhe*.
_S7_CIPHERS = (
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256"
)


# Siemens PLCs only accept a small set of TLS groups. X25519 is the group an
# S7-1500 negotiates in practice, so it is the only one worth naming here.
#
# There is deliberately NO fallback group. `set_ecdh_curve` can only name
# X25519 on OpenSSL builds that expose it as a curve (it raises on OpenSSL
# 3.0); where it raises, narrowing to something else is not a graceful
# degradation but a different, wrong answer — it restricts supported_groups to
# that group ALONE, and a PLC that wanted X25519 then RSTs during the
# handshake. Leaving the context untouched is strictly better: OpenSSL's
# default group list already offers X25519, and an untouched context also lets
# the documented OPENSSL_CONF `Groups` override actually take effect (a
# set_ecdh_curve call here would silently overwrite it).
_S7_PREFERRED_GROUPS = ("X25519",)


def _set_s7_groups(ctx: ssl.SSLContext) -> None:
    for group in _S7_PREFERRED_GROUPS:
        try:
            ctx.set_ecdh_curve(group)
            return
        except (ssl.SSLError, ValueError):
            continue
    logger.debug(
        "Could not restrict TLS groups to X25519 on this OpenSSL build; leaving "
        "the default group list, which offers X25519. If a PLC still rejects the "
        "handshake, restrict groups via OPENSSL_CONF (Groups = x25519)."
    )


# OMS legitimation derives its session key from the TLS exporter secret
# (RFC 5705). The label/length are fixed by the S7CommPlus protocol.
_OMS_EXPORTER_LABEL = b"EXPERIMENTAL_OMS"


_OMS_EXPORTER_LENGTH = 32


def _hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int, hashmod: Any) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label
    hkdf_label = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + hkdf_label + bytes([counter]), hashmod).digest()
        out += block
        counter += 1
    return out[:length]


def _tls13_exporter(exporter_master_secret: bytes, label: bytes, length: int, hashmod: Any) -> bytes:
    """RFC 8446 §7.5 TLS-Exporter with an empty context.

    Computed from the exporter_master_secret because CPython's ssl module
    does not expose ``export_keying_material``; we capture the secret via the
    TLS key log instead. Equivalent to ``SSL.export_keying_material`` for a
    TLS 1.3 session with no context.
    """
    empty_hash = hashmod(b"").digest()
    derived = _hkdf_expand_label(exporter_master_secret, label, empty_hash, hashmod().digest_size, hashmod)
    return _hkdf_expand_label(derived, b"exporter", empty_hash, length, hashmod)


@contextlib.contextmanager
def _tls_key_log(ctx: ssl.SSLContext) -> Iterator[str]:
    """Log the secrets of handshakes made with ``ctx`` to a private temp file.

    CPython's ssl cannot export RFC 5705 keying material, which OMS
    legitimation needs, so the TLS 1.3 exporter_master_secret is captured from
    the key log (written during the handshake) and the exporter is derived by
    ``_derive_oms_secret``. Yields the file's path. On exit the context stops
    logging, which closes the file it holds open (Windows cannot delete an
    open file), and the file is removed, also when the handshake fails. A file
    that cannot be removed is logged as a warning, by path only.
    """
    keylog_fd, keylog_path = tempfile.mkstemp(prefix="s7-tls-keylog-")
    os.close(keylog_fd)
    try:
        ctx.keylog_filename = keylog_path
        yield keylog_path
    finally:
        try:
            ctx.keylog_filename = None  # type: ignore[assignment]  # None disables the key log
        finally:
            try:
                os.unlink(keylog_path)
            except OSError as e:
                # Never the contents: the file holds the session's TLS secrets.
                logger.warning("Could not remove the TLS key log %s: %s", keylog_path, e.strerror or type(e).__name__)


def _derive_oms_secret(ssl_object: ssl.SSLObject, keylog_path: str) -> Optional[bytes]:
    """Derive the OMS exporter secret (RFC 5705) for legitimation.

    CPython's ssl module has no ``export_keying_material``, so we read the
    TLS 1.3 ``exporter_master_secret`` from the session key log written by
    ``_tls_key_log`` and run the RFC 8446 exporter derivation ourselves (stdlib
    hmac/hashlib only). Returns None (legitimation unavailable, anonymous
    reads still work) if the session isn't TLS 1.3 or the secret can't be
    recovered.
    """
    cipher = ssl_object.cipher()
    if not cipher or cipher[1] != "TLSv1.3":
        logger.warning(
            "OMS exporter derivation needs TLS 1.3 (session is %s)",
            cipher[1] if cipher else "unknown",
        )
        return None
    hashmod = hashlib.sha384 if cipher[0].endswith("SHA384") else hashlib.sha256

    exporter_master_secret = None
    try:
        with open(keylog_path, "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 3 and parts[0] == "EXPORTER_SECRET":
                    exporter_master_secret = bytes.fromhex(parts[2])
    except OSError as e:
        logger.warning("Could not read TLS key log: %s", e)
        return None

    if exporter_master_secret is None:
        logger.warning("EXPORTER_SECRET not found in TLS key log")
        return None

    oms_secret = _tls13_exporter(exporter_master_secret, _OMS_EXPORTER_LABEL, _OMS_EXPORTER_LENGTH, hashmod)
    logger.debug("OMS exporter secret derived (%d bytes)", len(oms_secret))
    return oms_secret


def _verify_pinned_certificate(ssl_object: ssl.SSLObject, expected: Optional[bytes]) -> Optional[bytes]:
    """Return the peer certificate's SHA-256 digest and enforce a pin if given.

    The digest is computed over the DER certificate the PLC presented in the
    handshake. When ``expected`` is set, a mismatch (or a missing certificate)
    raises ``S7CertificateError``; callers tear the connection down.
    """
    der = ssl_object.getpeercert(binary_form=True)
    observed = hashlib.sha256(der).digest() if der else None
    if expected is not None:
        if observed is None:
            raise S7CertificateError("PLC did not present a TLS certificate to pin")
        if not hmac.compare_digest(observed, expected):
            raise S7CertificateError(
                f"PLC TLS certificate does not match the pinned fingerprint (expected {expected.hex()}, got {observed.hex()})"
            )
    return observed
