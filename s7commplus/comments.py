"""Resolve the comments typed in TIA Portal onto the names `browse()` returns.

Two EXPLORE attributes carry them, compressed against Siemens preset
dictionaries. ``LineComm`` keys each block comment by a colon-joined path of
interface ids (``<Comment Path="52:51">``), which the block interface turns into
member names. A process area answers with ``IntfDescTag`` and ``TagLineComm``
instead, where the comment's ``RefID`` is the tag's LID.

A block does not always hold its own comments. An instance DB repeats its FB's
interface but none of the FB's comments, and the comments on a member typed
with a UDT or an FB sit on that UDT or FB. :class:`CommentCollector` therefore
takes the documents of every block and process area, which one EXPLORE of the
program returns, and resolves them together. It does no I/O, so both clients
share it and only send that EXPLORE.

Verified on S7-1500 V2 TLS sessions only.
"""

from __future__ import annotations

import logging
import re
import struct
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar

from .blob_decompressor import PresetStream, iter_preset_streams
from .block_interface import BlockInterface, BlockInterfaceError, Member, resolve_id_path
from .protocol import Ids
from .typeinfo import PROCESS_AREAS, START_OF_OBJECT, parse_object_list
from .vlq import decode_uint64_vlq

logger = logging.getLogger(__name__)

# The name `browse()` gives the tags of each process area, by the area's RID. A DB can have the same name.
_AREAS: dict[int, str] = {rid: name for name, rid, _ in PROCESS_AREAS}

# Program objects that can own an interface: DB, FB, FC, the two OB classes and UDT.
_BLOCK_CLASS_IDS = frozenset(
    {
        Ids.DB_CLASS_RID,
        Ids.FB_CLASS_RID,
        Ids.FC_CLASS_RID,
        Ids.CYCLIC_OB_CLASS_RID,
        Ids.PROGRAM_CYCLE_OB_CLASS_RID,
        Ids.UDT_CLASS_RID,
    }
)

_LINE_COMMENTS = "LineComm"
_TAG_COMMENTS = "TagLineComm"
_TAG_INTERFACE = "IntfDescTag"

_INDEX = re.compile(r"\[[^\]]*\]")


@dataclass(frozen=True)
class _BlockComments:
    """What one block or process area contributes to the comments.

    Comment texts are keyed by language, e.g. ``{"en-US": "Motor speed"}``, in
    the order the PLC sent them.

    Attributes:
        interface: The block interface. A process area's holds its tags as members, each
            with its LID as id and quoting the UDT it is typed with.
        line_comments: ``LineComm`` texts by interface id path; a process area's
            ``TagLineComm`` texts by LID, which is the id path of a tag.
    """

    interface: BlockInterface
    line_comments: Mapping[str, Mapping[str, str]]

    @classmethod
    def for_block(cls, streams: Iterable[PresetStream]) -> _BlockComments:
        """Parse the decompressed interface and ``LineComm`` documents of a block.

        Raises:
            ValueError: A comment or interface document is not well-formed XML, or the
                interface exceeds the limits of `parse_block_interface`.
        """
        streams = list(streams)
        return cls(interface=BlockInterface.from_streams(streams), line_comments=_parse_comments(streams, _LINE_COMMENTS, "Path"))

    @classmethod
    def for_area(cls, streams: Iterable[PresetStream]) -> _BlockComments:
        """Parse the decompressed ``IntfDescTag`` and ``TagLineComm`` documents of a process area.

        Raises:
            BlockInterfaceError: A document is not well-formed XML.
        """
        streams = list(streams)
        tags = BlockInterface.from_tag_xml(stream.text for stream in streams if stream.preset.kind == _TAG_INTERFACE)
        # a TagLineComm's RefID is the tag's LID, which from_tag_xml gives each tag as its id
        return cls(interface=tags, line_comments=_parse_comments(streams, _TAG_COMMENTS, "RefID"))


def _parse_comments(streams: Iterable[PresetStream], kind: str, key: str) -> dict[str, dict[str, str]]:
    """Read ``{key: {language: text}}`` out of the ``<Comment>`` entries of the `kind` documents among `streams`.

    An entry without `key` is skipped and logged: a ``LineComm`` also carries texts keyed by
    ``UId``/``RefID`` that belong to no member, such as a library block's description or the
    alarm texts of a GRAPH sequence.

    Raises:
        BlockInterfaceError: A document is not well-formed XML.
    """
    comments: dict[str, dict[str, str]] = {}
    skipped = 0
    for stream in streams:
        if stream.preset.kind != kind:
            continue
        try:
            document = stream.xml
        except ET.ParseError as exc:
            raise BlockInterfaceError(f"{kind} document is not well-formed XML: {exc}") from exc
        for comment in document.iter("Comment"):
            if (value := comment.get(key)) is None:
                skipped += 1
                continue
            texts = comments.setdefault(value, {})
            for entry in comment.iter("DictEntry"):
                texts[entry.get("Language", "")] = entry.text or ""
    if skipped:
        logger.debug("Skipping %d comments without a %s attribute", skipped, key)
    return comments


class Comments(Mapping[str, str]):
    """Comments keyed by the variable names `browse()` returns, e.g. ``"Motors.speed[1]"`` or ``"IArea.Start"``.

    ``comments[name]`` is the text in the first language the PLC sent.

    Example::

        comments = client.get_comments()
        for variable in client.browse():
            print(variable["name"], comments.find(variable["name"]))
    """

    def __init__(self, entries: Mapping[str, Mapping[str, str]]) -> None:
        self._entries = {name: dict(texts) for name, texts in entries.items() if texts}
        # Where the entries of each name without indexes keep indexes: find() tries only these layouts,
        # at most one per stored layout, instead of every subset of the name's indexes (2**n for n of them)
        self._layouts: dict[str, set[frozenset[int]]] = {}
        for entry in self._entries:
            shape, indexes = _split_indexes(entry)
            self._layouts.setdefault(shape, set()).add(frozenset(offset for offset, _ in indexes))

    def __getitem__(self, name: str) -> str:
        return next(iter(self._entries[name].values()))

    def __iter__(self) -> Iterator[str]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def languages(self, name: str) -> dict[str, str]:
        """Every text of a comment by language, or an empty dict when `name` has no comment of its own."""
        return dict(self._entries.get(name, {}))

    def find(self, name: str, language: str | None = None) -> str | None:
        """The comment of a variable, of the array the variable is an element of, or of its field in every element.

        A comment written on an array belongs to every element, so ``"DB.values[3]"``
        falls back to ``"DB.values"``, and one written on a field of a Struct or UDT
        array belongs to that field in every element, so ``"DB.motors[1].speed"``
        falls back to ``"DB.motors.speed"``. A structure's members do not inherit its
        comment: ``"DB.motors[1].speed"`` never falls back to ``"DB.motors"``.

        Every index can be dropped this way, the innermost ones first and the fewest
        at a time: ``"DB.motors[1].speeds[2]"`` tries ``"DB.motors[1].speeds"``, then
        ``"DB.motors.speeds[2]"``, then ``"DB.motors.speeds"``.

        Args:
            name: Variable name as `browse()` returns it.
            language: Language of the text, e.g. ``"en-US"``; None takes the first one.

        Returns:
            The text, or None when none of these has a comment in that language.
        """
        shape, indexes = _split_indexes(name)
        offsets = [offset for offset, _ in indexes]
        # a layout fits when the name has an index at every offset it keeps
        layouts = [layout for layout in self._layouts.get(shape, ()) if layout.issubset(offsets)]
        # the fewest dropped first, then the innermost: the dropped positions counted from the last index
        layouts.sort(
            key=lambda layout: (
                -len(layout),
                sorted(len(offsets) - 1 - i for i, offset in enumerate(offsets) if offset not in layout),
            )
        )
        for layout in layouts:
            # put the indexes the layout keeps back into the shape
            parts: list[str] = []
            last = 0
            for offset, index in indexes:
                if offset in layout:
                    parts += [shape[last:offset], index]
                    last = offset
            candidate = "".join([*parts, shape[last:]])
            texts = self._entries.get(candidate, {})
            if (text := next(iter(texts.values()), None) if language is None else texts.get(language)) is not None:
                return text
        return None


def _split_indexes(name: str) -> tuple[str, list[tuple[int, str]]]:
    """Split ``"DB.m[1].s[2,3]"`` into ``"DB.m.s"`` and each index with its offset there, ``[(4, "[1]"), (6, "[2,3]")]``."""
    shape: list[str] = []
    indexes: list[tuple[int, str]] = []
    offset = last = 0
    for matched in _INDEX.finditer(name):
        shape.append(name[last : matched.start()])
        offset += matched.start() - last
        indexes.append((offset, matched.group()))
        last = matched.end()
    shape.append(name[last:])
    return "".join(shape), indexes


class CommentCollector:
    """Collect the names, interfaces and comments of the program, and resolve the comments onto variable names.

    Sans-IO: the caller explores the program with `ATTRIBUTES` and hands the payload over::

        payload = client.explore(Ids.NATIVE_THE_PLC_PROGRAM_RID, CommentCollector.ATTRIBUTES)
        comments = CommentCollector(payload).resolve()

    That one payload holds the name and documents of every block and process area, each as
    attributes of its object. An object whose interface or comment document is corrupt is
    skipped and logged.

    Args:
        explore_payload: The EXPLORE reply of the program.

    Raises:
        ValueError: If the payload is truncated or its object tree is malformed.
    """

    # The attributes the program is explored with: each object's name, interface and comments.
    ATTRIBUTES: ClassVar[tuple[int, ...]] = (
        Ids.OBJECT_VARIABLE_TYPE_NAME,
        Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION,
        Ids.DATA_INTERFACE_LINE_COMMENTS,
    )

    def __init__(self, explore_payload: bytes) -> None:
        try:
            _return_value, offset = decode_uint64_vlq(explore_payload, 0)
            offset = explore_payload.find(START_OF_OBJECT, offset)
            pending = parse_object_list(explore_payload, offset)[0] if offset >= 0 else []
        except (struct.error, IndexError, RecursionError) as exc:
            raise ValueError(f"Program EXPLORE payload is truncated or malformed: {exc}") from exc
        self._roots: list[str] = []
        self._blocks: dict[str, _BlockComments] = {}
        self._areas: dict[int, _BlockComments] = {}
        while pending:
            obj = pending.pop()
            pending.extend(obj.objects)
            rid = obj.relation_id
            raw_name = obj.attributes.get(Ids.OBJECT_VARIABLE_TYPE_NAME, b"")
            # as client._parse_program_objects decodes it: an S7-1500 sends the ASCII range one byte per character
            name = raw_name.decode("utf-16-be" if b"\x00" in raw_name else "latin-1", errors="replace").rstrip("\x00")
            if rid not in _AREAS and not (name and obj.class_id in _BLOCK_CLASS_IDS):
                continue
            # a data block, as ProgramObject.is_datablock tells it
            if obj.class_id == Ids.DB_CLASS_RID and rid >> 16 == 0x8A0E:
                self._roots.append(name)
            # an S7-1500 puts a version before each stream and its checksum after it, so the streams are searched for
            streams = [
                stream for attribute in self.ATTRIBUTES for stream in iter_preset_streams(obj.attributes.get(attribute, b""))
            ]
            if not streams:
                continue
            try:
                if rid in _AREAS:
                    self._areas[rid] = _BlockComments.for_area(streams)
                else:
                    self._blocks[name] = _BlockComments.for_block(streams)
            except ValueError as exc:
                logger.warning("Skipping the comments of object 0x%08X: %s", rid, exc)

    def resolve(self, max_comments: int = 1_000_000, max_depth: int = 64) -> Comments:
        """Resolve the comments of the data blocks and process areas added so far onto variable names.

        A member typed with a UDT or an FB takes that block's comments, and a DB
        those of the FB or UDT it is declared with, which resolve against the DB's own
        interface because it repeats their ids. Comments the block writes itself win
        over both, language by language. A DB can have the name of a process area, as
        in `browse()`; a member and a tag of the same name then share the entry, and
        the tag's comment wins for a language both have.

        Every member typed with a block gets a copy of that block's comments, so a few
        nested UDTs can multiply into very many names; the limits stop a program, or a
        PLC, that expands them without bound.

        Args:
            max_comments: The most comments the blocks may resolve to, counted over every block and copy.
            max_depth: The most levels of blocks typed with a block, such as UDTs nested in UDTs.

        Raises:
            ValueError: The comments exceed `max_comments`, or the blocks nest deeper than `max_depth`.
        """
        resolver = _Resolver(self._blocks, max_comments, max_depth)
        return Comments(resolver.program(self._roots, self._areas))


class _Resolver:
    """Resolves each block's comments onto its member names, within the limits of `CommentCollector.resolve`."""

    def __init__(self, blocks: Mapping[str, _BlockComments], max_comments: int, max_depth: int) -> None:
        self._blocks = blocks
        self._types = {name: block.interface.members for name, block in blocks.items()}
        self._max_comments = max_comments
        self._max_depth = max_depth
        self._count = 0
        # The blocks on the way down to the one being resolved
        self._resolving: list[str] = []
        # Each block's comments, resolved once however many members are typed with it
        self._resolved: dict[str, dict[str, dict[str, str]]] = {}

    def program(self, roots: Iterable[str], areas: Mapping[int, _BlockComments]) -> dict[str, dict[str, str]]:
        """The comments of the data blocks `roots` and of the process areas, by variable name."""
        result = {f"{name}.{path}": texts for name in roots if name in self._blocks for path, texts in self.block(name).items()}
        for rid, area in areas.items():
            for path, texts in self.comments(area).items():
                self.merge(result, f"{_AREAS[rid]}.{path}", texts)
        return result

    def merge(self, comments: dict[str, dict[str, str]], name_path: str, texts: Mapping[str, str]) -> None:
        if name_path not in comments:
            self._count += 1
            if self._count > self._max_comments:
                raise ValueError(f"Comments resolve to more than {self._max_comments} names")
        comments[name_path] = {**comments.get(name_path, {}), **texts}

    def block(self, block_name: str) -> dict[str, dict[str, str]]:
        if block_name not in self._resolved:
            if len(self._resolving) > self._max_depth:
                raise ValueError(f"Blocks typed with blocks nest deeper than {self._max_depth} levels")
            self._resolving.append(block_name)
            self._resolved[block_name] = self.comments(self._blocks[block_name])
            self._resolving.pop()
        return self._resolved[block_name]

    def comments(self, block: _BlockComments) -> dict[str, dict[str, str]]:
        comments: dict[str, dict[str, str]] = {}
        for owner_path, member in _own_members(block.interface.members):
            typed_with = member.typed_block
            # A block on the way down is typed with itself, directly or through others: its copy would never end
            if typed_with is not None and typed_with in self._blocks and typed_with not in self._resolving:
                for path, typed_texts in self.block(typed_with).items():
                    self.merge(comments, f"{owner_path}.{path}", typed_texts)

        source = block.interface.source
        inherited = self._blocks[source].line_comments if source and source in self._blocks else {}
        for line_comments in (inherited, block.line_comments):
            for id_path, texts in line_comments.items():
                if name_path := resolve_id_path(block.interface.members, id_path, types=self._types):
                    self.merge(comments, name_path, texts)
        return comments


def _own_members(members: Sequence[Member], prefix: str = "") -> Iterator[tuple[str, Member]]:
    """Yield ``(name_path, member)`` for every member a block declares itself, inline Struct fields included.

    The fields of a member typed with a UDT or an FB belong to that block, which holds their comments.
    """
    for member in members:
        name_path = f"{prefix}{member.name}"
        yield name_path, member
        if member.typed_block is None and member.element_type == "Struct":
            yield from _own_members(member.fields, f"{name_path}.")
