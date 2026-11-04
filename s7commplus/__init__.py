"""S7CommPlus protocol client for S7-1200/1500 PLCs.

Pure Python implementation of the S7CommPlus protocol for direct
communication with Siemens S7-1200 and S7-1500 PLCs. For legacy
S7-300/400 PLCs, use ``snap7.Client`` instead.

Usage::

    from s7commplus import Client

    client = Client()
    client.connect("192.168.1.10")
    data = client.db_read(1, 0, 4)
"""

from .async_client import AsyncSubscriptionQueue
from .async_client import S7CommPlusAsyncClient as AsyncClient
from .alarm import Alarm, AlarmNotification, AlarmText, LanguageId
from .blob_decompressor import (
    PresetStream,
    decompress_blob,
    find_and_decompress,
    find_preset_stream,
    iter_preset_headers,
    iter_preset_streams,
)
from .block_interface import BlockInterface, Member, block_interface_from_explore, resolve_id_path
from .catalog import ArrayDimension, SymbolCatalog, SymbolicTag, TagResult
from .client import DBWriteItem, ProgramObject, SymbolicReadItem
from .client import S7CommPlusClient as Client
from .connection import S7CommPlusConnection
from .devices import DEVICE_NAMES, device_family, device_name
from .object_model import attribute_name, describe_attribute
from .server import CPUState, DataBlock
from .server import S7CommPlusServer as Server
from .subscription import SubscriptionDiagnostics, SubscriptionItem, SubscriptionNotification, SubscriptionRestoreResult
from .tag_browser import (
    DataBlock as ExploreDataBlock,
)
from .tag_browser import (
    Tag,
    datablocks_from_explore,
    tags_from_explore,
)
from .zlib_dicts import PresetIdentity

__all__ = [
    "Alarm",
    "AlarmNotification",
    "AlarmText",
    "ArrayDimension",
    "AsyncClient",
    "AsyncSubscriptionQueue",
    "BlockInterface",
    "CPUState",
    "Client",
    "DBWriteItem",
    "DataBlock",
    "DEVICE_NAMES",
    "ExploreDataBlock",
    "LanguageId",
    "Member",
    "PresetIdentity",
    "PresetStream",
    "ProgramObject",
    "S7CommPlusConnection",
    "Server",
    "SubscriptionItem",
    "SubscriptionNotification",
    "SubscriptionRestoreResult",
    "SubscriptionDiagnostics",
    "SymbolCatalog",
    "SymbolicReadItem",
    "SymbolicTag",
    "Tag",
    "TagResult",
    "block_interface_from_explore",
    "datablocks_from_explore",
    "decompress_blob",
    "attribute_name",
    "describe_attribute",
    "device_family",
    "device_name",
    "find_and_decompress",
    "find_preset_stream",
    "iter_preset_headers",
    "iter_preset_streams",
    "resolve_id_path",
    "tags_from_explore",
]
