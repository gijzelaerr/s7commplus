"""Response-value layouts observed on S7-1512SP FW 2.6 and the emulator."""

from unittest.mock import AsyncMock

import pytest

from s7commplus.async_client import S7CommPlusAsyncClient
from s7commplus.connection import _parse_get_var_substreamed_response
from s7commplus.error import S7ConnectionError

# Decoded application payload, with the session-specific challenge replaced.
_CHALLENGE = bytes(range(20))


@pytest.mark.parametrize("marker", [b"", b"\x00"])
def test_challenge_payload_with_trailing_integrity_id(marker: bytes) -> None:
    payload = b"\x00" + marker + b"\x10\x02\x14" + _CHALLENGE + b"\x04\x00\x00\x00\x00"
    assert _parse_get_var_substreamed_response(payload) == _CHALLENGE


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x00\x10", b"\x00\x10\x02\x14\x01"])
def test_truncated_challenge_is_rejected(payload: bytes) -> None:
    with pytest.raises(S7ConnectionError, match="Malformed"):
        _parse_get_var_substreamed_response(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("marker", [b"", b"\x00"])
async def test_async_challenge_uses_shared_parser(marker: bytes) -> None:
    client = S7CommPlusAsyncClient()
    client._connection.send_request = AsyncMock(return_value=b"\x00" + marker + b"\x10\x02\x14" + _CHALLENGE + b"\x04")
    assert await client._connection._get_legitimation_challenge() == _CHALLENGE
