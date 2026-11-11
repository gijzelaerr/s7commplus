"""
S7 error handling and exception classes.

Maps S7 error codes to Python exceptions with meaningful messages.
"""

import copyreg
from typing import Optional, Any

from .protocol import service_result_code


class S7Error(Exception):
    """Base exception for all S7 protocol errors."""

    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code

    def __reduce__(self) -> tuple[Any, ...]:
        # Rebuild without calling __init__, so subclasses whose constructor takes
        # other arguments than the message still pickle and copy.
        return copyreg.__newobj__, (type(self), *self.args), self.__dict__  # type: ignore[attr-defined]


class S7ConnectionError(S7Error):
    """Raised when connection to S7 device fails."""

    pass


class S7NotConnectedError(S7ConnectionError, RuntimeError):
    """Raised when a client call needs a connection and there is none.

    Also a ``RuntimeError``, which the clients raised for this before, so code
    catching that keeps working.
    """

    pass


class S7ProtocolError(S7Error):
    """Raised when S7 protocol communication fails."""

    pass


class S7IntegrityError(S7ProtocolError):
    """Raised when authenticated S7CommPlus traffic fails integrity checks."""

    pass


class S7ReturnValueError(S7ProtocolError):
    """Raised when the PLC answers a request with an error ReturnValue.

    Attributes:
        return_value: The full 64-bit ReturnValue; `error_code` holds the signed code from its low 16 bits.
        response: The raw response payload, starting with the ReturnValue.
    """

    def __init__(self, message: str, return_value: int, response: bytes):
        super().__init__(message, error_code=service_result_code(return_value))
        self.return_value = return_value
        self.response = response


class S7TimeoutError(S7Error):
    """Raised when S7 operation times out."""

    pass


class S7AuthenticationError(S7Error):
    """Raised when S7 authentication fails."""

    pass


class S7CertificateError(S7ConnectionError):
    """Raised when a PLC's TLS certificate fails verification or pinning."""

    pass


class S7TlsHandshakeError(S7ConnectionError):
    """Raised when the TLS handshake with the PLC does not complete.

    The underlying ``ssl``/socket error is the exception's ``__cause__``. A
    certificate that fails verification raises :class:`S7CertificateError`
    instead.
    """

    pass


class S7RateLimitError(S7Error):
    """Raised when a non-blocking request rate limit is reached."""

    pass


class S7WriteError(S7Error, RuntimeError):
    """A multi-item write that did not write every item.

    ``db_write_multi`` raises it when the PLC refuses items, and when a batch
    split over several requests is interrupted after its first request; the
    interrupting exception is then its ``__cause__``. ``write_tags`` attaches
    it to the tags an interrupted batch left unconfirmed. It is also a
    ``RuntimeError``, which ``db_write_multi`` raised for refused items before.

    Positions are 1-based and count across the whole batch. Every position not
    in ``item_errors``, ``unknown`` or ``not_sent`` was written.

    Attributes:
        item_errors: The PLC error of each refused item, by position. An item
            of a request the PLC refused as a whole has that request's return
            value. ``write_tags`` reports refusals on their own tags and leaves
            this empty.
        unknown: Positions in the request that was in flight when the batch
            was interrupted: the PLC may or may not have written them.
        not_sent: Positions after it, which were never sent.
    """

    def __init__(
        self,
        message: str,
        item_errors: Optional[dict[int, int]] = None,
        unknown: Optional[range] = None,
        not_sent: Optional[range] = None,
    ) -> None:
        super().__init__(message)
        self.item_errors: dict[int, int] = dict(item_errors or {})
        self.unknown: range = unknown if unknown is not None else range(0)
        self.not_sent: range = not_sent if not_sent is not None else range(0)


class S7SubscriptionError(S7Error, RuntimeError):
    """``create_subscriptions`` stopped after creating some of its subscriptions.

    The error that stopped it is the ``__cause__``. Like the PLC's refusal of a
    subscription, it is also a ``RuntimeError``.

    Attributes:
        created: IDs of the subscriptions already created, which cover the
            first items in order. They stay active and registered.
    """

    def __init__(self, message: str, created: list[int]) -> None:
        super().__init__(message)
        self.created: list[int] = list(created)


class S7StalePacketError(S7ProtocolError):
    """Raised when a response has an old/stale PDU reference number."""

    pass


class S7PacketLostError(S7ProtocolError):
    """Raised when a response PDU reference is ahead of expected (packet loss)."""

    pass
