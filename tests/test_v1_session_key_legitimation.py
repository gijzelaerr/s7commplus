"""Vector test for LegitimateScheme solver."""

from __future__ import annotations

from unittest.mock import patch

from s7commplus.v1_session_key.keys import KeyFamily
from s7commplus.v1_session_key.legitimation import solve_legitimate_challenge_real_plc


def test_solve_legitimate_challenge_real_plc_vector() -> None:
    challenge = bytes([0x66] * 20)
    public_key = bytes.fromhex("e0e1f04a5ca3f90148178689bd0c930ab9db867b4f0ab109623959aa32316b7880ed1b4f9a9b189f")
    session_key = bytes.fromhex("65c4f179980a43cb60e1194ba500f5b9d04f374b56374866")
    expected = bytes(
        [
            0xEF,
            0xBE,
            0xAD,
            0xDE,
            0x7C,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x1A,
            0x73,
            0x08,
            0x1F,
            0x09,
            0x6B,
            0x42,
            0xBD,
            0x10,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x2F,
            0xB8,
            0x46,
            0xC1,
            0xF4,
            0x78,
            0xFE,
            0xB0,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x3C,
            0x00,
            0x00,
            0x00,
            0xDE,
            0xFC,
            0xE0,
            0xE5,
            0x0B,
            0xED,
            0x8B,
            0x8A,
            0xA8,
            0xC8,
            0x8F,
            0xEC,
            0xCB,
            0x0A,
            0xA8,
            0x41,
            0x25,
            0xEA,
            0x80,
            0xF6,
            0x97,
            0x56,
            0x1E,
            0xCB,
            0x1A,
            0xA3,
            0xEF,
            0x70,
            0x7A,
            0x7A,
            0xCF,
            0x18,
            0xA7,
            0xD5,
            0x29,
            0xFE,
            0x21,
            0x9D,
            0x55,
            0xE7,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0x2D,
            0xEF,
            0xBE,
            0xAD,
            0xDE,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x00,
            0x00,
            0x00,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0x25,
            0xB7,
            0xC9,
            0xC2,
            0x84,
            0xBD,
            0xC8,
            0x5B,
            0x31,
            0x66,
            0x93,
            0x7B,
            0x26,
            0x92,
            0xDB,
            0x32,
            0x9C,
            0xDE,
            0x73,
            0x4E,
            0x40,
            0x34,
            0x18,
            0xE5,
            0xBB,
            0xCC,
            0x45,
            0x0D,
            0x0B,
            0xE5,
            0xD3,
            0xA7,
            0x76,
            0x7B,
            0x6A,
            0xEC,
            0x2F,
            0x60,
            0x3D,
            0xAA,
            0xE0,
            0x15,
            0x61,
            0x57,
            0x48,
            0x5A,
            0x84,
            0x2A,
            0x7D,
            0xEF,
            0xBE,
            0xAD,
            0xDE,
            0x01,
            0x00,
            0x00,
            0x00,
            0x18,
            0x00,
            0x00,
            0x00,
            0xC4,
            0x6E,
            0x9C,
            0x19,
            0x4E,
            0x78,
            0x15,
            0xA3,
            0x92,
            0xE8,
            0x68,
            0xCA,
            0x9D,
            0xAD,
            0xA9,
            0xAA,
            0xBA,
            0x2E,
            0x60,
            0xEB,
            0x7E,
            0x70,
            0xD3,
            0x01,
            0xEF,
            0xBE,
            0xAD,
            0xDE,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )

    index = [0]
    fill_seq = [0x25, 0x2D, 0x2D]

    def mock_urandom(n: int) -> bytes:
        b = fill_seq[index[0]]
        index[0] = (index[0] + 1) % len(fill_seq)
        return bytes([b] * n)

    with patch("os.urandom", mock_urandom):
        result = solve_legitimate_challenge_real_plc(challenge, public_key, KeyFamily.S7_1200, session_key, "zaq1@WSX")

    assert result == expected


def test_solve_legitimate_challenge_plcsim_vector() -> None:
    """HarpoS7 ``LegitimateSchemeTests.SolveLegitimateChallengePlcSimHashTest``."""
    from s7commplus.v1_session_key.legitimation import solve_legitimate_challenge_plcsim

    challenge = bytes([0x66] * 20)
    public_key = bytes.fromhex(
        "4700db8fa25d791c2a77eec9795d66e3b5f2ba9a59508add510ca9fe8762aa08"
        "1dff80ea8f730ad4caa0bca7ba92892c691984338eec2047681d958dc5c5086a"
    )
    session_key = bytes.fromhex("37a97bebd48c8d2c67838b858c4aab4defa6897cd338f70b")
    password_hash = bytes.fromhex("eb54af6d27b89f75f16244b79295c40abc306e39")
    expected = bytes.fromhex(
        "efbeaddea00000000100000002000000000000000004000000000000ca4aaa9c"
        "ac5476b010030000000000007c5fe40fd8b8f7ca010300000000000060000000"
        "51a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d"
        "0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1"
        "feceec9b9cf981881ef8c4b671796de71ebca34d1e2bc03e474d6a82117dfa56"
        "efbeadde0000000040000000cccccccccccccccccccccccccccccccc0762bee8"
        "3ebeaf5704db6388c960eaece090b8c9b4b5ac0ffc55fc25919ca1beb97e951d"
        "4bdaed990f0e9a94442d1f41efbeadde01000000180000004070a5ee93a24eab"
        "8362d8ba317b253e4cd5206ba34c8e03efbeadde0200000000000000"
    )

    # The seed's ECIES scalar is random; inject HarpoS7's seed and IV so the
    # expected blob pins the metadata, AES-GCM and layout. The seed generator has
    # its own HarpoS7 known-answer test in test_v1_session_key_plcsim.py, and the
    # real-PLC vector above pins the shared metadata writer.
    blob = solve_legitimate_challenge_plcsim(
        challenge,
        public_key,
        session_key,
        password_hash=password_hash,
        seed=expected[0x40:0xA0],
        iv=expected[0xAC:0xBC],
    )

    assert blob == expected


def test_v1_legitimation_payload_layout_plcsim() -> None:
    """The SET_VAR_SUBSTREAMED legitimation request layout PLCSIM accepts."""
    from s7commplus.connection import _build_v1_legitimation_payload

    payload = _build_v1_legitimation_payload(0x70000F8F, 5, b"\xaa" * 8, KeyFamily.PLCSIM)

    assert payload == bytes.fromhex(
        "70000f8f"  # InObjectId
        "200401"  # item intro
        "8e36"  # address 1846 (VLQ)
        "000004e88969001200000000896a001300896b000400000001"  # object qualifier, key qualifier 1
        "001400"  # fill, BLOB, fill
        "08"  # blob length (VLQ)
        "aaaaaaaaaaaaaaaa"  # blob
        "00000000"  # trailing fill (IntegrityId spliced before it)
    )


def test_v1_legitimation_payload_layout_real_plc() -> None:
    """S7-1200 and S7-1500 keep the pre-existing (master) legitimation layout byte-for-byte."""
    from s7commplus.connection import _build_v1_legitimation_payload

    expected = bytes.fromhex(
        "00001234"  # InObjectId
        "2004"  # item intro
        "01"  # ItemNumber
        "8e36"  # address 1846 (VLQ)
        "000004e88969001200000000896a001300896b000400000007"  # object qualifier, key qualifier = sequence
        "01"  # ItemNumber for the value
        "001400"  # fill, BLOB, fill
        "04"  # blob length (VLQ)
        "01020304"  # blob
        "07"  # sequence number (VLQ)
        "000000"  # trailing fill (IntegrityId spliced before it)
    )

    for family in (KeyFamily.S7_1200, KeyFamily.S7_1500):
        assert _build_v1_legitimation_payload(0x1234, 7, b"\x01\x02\x03\x04", family) == expected


def test_v1_legitimation_integrity_tail_is_gated_on_family() -> None:
    from s7commplus.connection import _v1_legitimation_integrity_tail

    assert _v1_legitimation_integrity_tail(KeyFamily.PLCSIM) == 4
    assert _v1_legitimation_integrity_tail(KeyFamily.S7_1200) == 3
    assert _v1_legitimation_integrity_tail(KeyFamily.S7_1500) == 3
