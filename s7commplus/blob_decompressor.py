"""Decompress zlib-compressed blobs from S7-1200/1500 PLCs.

S7CommPlus PLCs compress XML metadata (tag definitions, network comments,
interface descriptions, etc.) using zlib with Siemens-specific preset
dictionaries. Python's ``zlib.decompress()`` returns ``Z_NEED_DICT`` for
these blobs; this module supplies the matching dictionary.

The 19 preset dictionaries were extracted from thomas-v2/S7CommPlusDriver
(LGPL-3.0) and are stored in ``zlib_dicts.py``.

Usage::

    data = decompress_blob(compressed_bytes)
    # data is the decompressed XML string (UTF-8)
"""

import logging
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from .zlib_dicts import ZLIB_DICTIONARIES, ZLIB_DICT_NAMES, ZLIB_DICT_IDENTITIES, PresetIdentity

logger = logging.getLogger(__name__)


def decompress_blob(data: bytes, offset: int = 0) -> str:
    """Decompress a zlib blob, auto-supplying the preset dictionary if needed.

    Args:
        data: Raw bytes containing the zlib stream.
        offset: Starting position within ``data``. Some blobs have a
            4-byte version prefix before the zlib header.

    Returns:
        Decompressed content as a UTF-8 string.

    Raises:
        ValueError: If the zlib stream requires an unknown dictionary.
        zlib.error: On other decompression failures.
    """
    # A view, not a copy: iter_preset_streams calls this once per candidate header,
    # and each slice used to copy the rest of a possibly multi-MB EXPLORE payload.
    stream = memoryview(data)[offset:]

    # Check for preset-dictionary zlib header: CMF=0x78, FLG with FDICT bit set (bit 5)
    if len(stream) >= 6 and stream[0] == 0x78 and (stream[1] & 0x20):
        dict_adler = int.from_bytes(stream[2:6], "big")
        zdict = ZLIB_DICTIONARIES.get(dict_adler)
    else:
        # Standard zlib stream — no preset dictionary
        return zlib.decompress(stream).decode("utf-8")

    # Preset dictionary required

    if zdict is None:
        name = ZLIB_DICT_NAMES.get(dict_adler, "unknown")
        raise ValueError(
            f"Unknown zlib preset dictionary: adler32=0x{dict_adler:08x} ({name}). "
            f"Known dictionaries: {', '.join(ZLIB_DICT_NAMES.values())}"
        )

    logger.debug("Using preset dictionary: %s (0x%08x)", ZLIB_DICT_NAMES.get(dict_adler, "?"), dict_adler)

    dobj = zlib.decompressobj(wbits=-15, zdict=zdict)
    # Skip the 6-byte zlib header (2 magic + 4 dict adler)
    result = dobj.decompress(stream[6:])
    return result.decode("utf-8")


@dataclass(frozen=True)
class PresetStream:
    """A decompressed preset-dictionary zlib stream.

    Attributes:
        preset: The preset dictionary the stream was compressed against.
        text: The decompressed XML document.
    """

    preset: PresetIdentity
    text: str

    @property
    def xml(self) -> ET.Element:
        """Parse `text` into an element tree; every access parses anew.

        Returns:
            The root element of the document.

        Raises:
            xml.etree.ElementTree.ParseError: If the PLC sent text that is not well-formed XML.
        """
        return ET.fromstring(self.text)


def iter_preset_headers(data: bytes) -> Iterator[tuple[int, PresetIdentity]]:
    """Yield the offset and dictionary of every preset-dictionary zlib header in `data`.

    Lets a caller pick a stream by its dictionary before decompressing anything. A match can
    still be a coincidence inside compressed data, which only shows when decompressing from it
    fails.

    Args:
        data: Raw EXPLORE response payload (possibly multi-fragment).

    Returns:
        An iterator of `(offset, preset)` in the order the headers appear.
    """
    # CMF 0x78 is deflate with a 32K window, the only CMF the PLC emits.
    position = data.find(0x78)
    while position >= 0:
        header = data[position : position + 6]
        # FDICT flag (bit 5) set and the two header bytes a multiple of 31 (zlib's FCHECK rule).
        if len(header) == 6 and header[1] & 0x20 and int.from_bytes(header[:2], "big") % 31 == 0:
            preset = ZLIB_DICT_IDENTITIES.get(int.from_bytes(header[2:], "big"))
            if preset is not None:
                yield position, preset
        position = data.find(0x78, position + 1)


def iter_preset_streams(data: bytes) -> Iterator[PresetStream]:
    """Yield every preset-dictionary zlib stream in `data`, in the order they appear.

    Decompresses each header from `iter_preset_headers`. A header that falls
    inside compressed data usually fails to decode and is skipped, as is a stream that
    decompresses to an empty document.

    The example matches on `preset.kind` alone, so it accepts either `LineComm`
    version. Comments are keyed by `Path` in the `0x98000001` layout, the only
    one observed on S7-1500 PLCs; the `0x90000001` dictionary suggests
    `UId`/`LineId` instead.

    Example::

        from s7commplus import Client, iter_preset_streams
        from s7commplus.protocol import Ids

        with Client() as client:
            client.connect("192.168.1.10", use_tls=True)
            raw = client.explore(Ids.NATIVE_THE_PLC_PROGRAM_RID, [Ids.DATA_INTERFACE_LINE_COMMENTS])
            for stream in iter_preset_streams(raw):
                if stream.preset.kind == "LineComm":
                    for comment in stream.xml.iter("Comment"):
                        for entry in comment.iter("DictEntry"):
                            print(comment.get("Path"), entry.get("Language"), entry.text)

    Args:
        data: Raw EXPLORE response payload (possibly multi-fragment).

    Returns:
        An iterator of `PresetStream` for each decodable stream.
    """
    for offset, preset in iter_preset_headers(data):
        try:
            text = decompress_blob(data, offset=offset)
        except (ValueError, zlib.error) as e:
            logger.debug("Skipping %s 0x%08x stream at offset %d: %s", preset.kind, preset.version, offset, e)
            continue
        if not text:
            logger.debug("Skipping empty %s 0x%08x stream at offset %d", preset.kind, preset.version, offset)
            continue
        yield PresetStream(preset, text)


def find_and_decompress(data: bytes) -> str | None:
    """Scan raw bytes for a zlib stream with preset dictionary and decompress it.

    Searches for the ``78 7D`` magic (zlib level 6 + FDICT flag) that
    indicates a preset-dictionary stream. Falls back to ``78 01``/``78 5E``/
    ``78 9C``/``78 DA`` for standard streams.

    Args:
        data: Raw EXPLORE response payload (possibly multi-fragment).

    Returns:
        Decompressed UTF-8 string, or ``None`` if no zlib stream found.
    """
    # Preset-dictionary magic: CMF=0x78 (deflate, window=32K), FLG=0x7D (FDICT set)
    for magic in (b"\x78\x7d", b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        pos = data.find(magic)
        if pos >= 0:
            try:
                return decompress_blob(data, offset=pos)
            except (ValueError, zlib.error) as e:
                logger.debug("Decompression failed at offset %d: %s", pos, e)
                continue
    return None
