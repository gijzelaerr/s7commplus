"""
S7CommPlus protocol constants and types.

Defines the protocol framing, opcodes, function codes, data types,
element IDs, and other constants needed for S7CommPlus communication.

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
Reference: Wireshark S7CommPlus dissector
"""

import functools
from enum import IntEnum, IntFlag


# Protocol identification byte (vs 0x32 for legacy S7comm)
PROTOCOL_ID = 0x72


class ProtocolVersion(IntEnum):
    """S7CommPlus protocol versions.

    V1: Non-TLS sessions, optionally with legacy SessionKey authentication
        (observed on S7-1200 FW V4.2 and S7-1500 FW V2.6)
    V2: Adds integrity checking and session authentication
    V3: Adds public-key-based key exchange
    TLS: TIA Portal V17+ -- standard TLS 1.3 with per-device certificates

    For new implementations, TLS (V3 + InitSsl) is the recommended target.
    """

    V1 = 0x01
    V2 = 0x02
    V3 = 0x03
    SYSTEM_EVENT = 0xFE


class Opcode(IntEnum):
    """S7CommPlus opcodes (first byte after header)."""

    REQUEST = 0x31
    RESPONSE = 0x32
    NOTIFICATION = 0x33
    RESPONSE2 = 0x02  # Seen in some older firmware


class FunctionCode(IntEnum):
    """S7CommPlus function codes.

    These identify the type of operation in a request/response pair.
    Value sequence 1211-1434 (decimal) matches the RequestRID tables in
    Wireshark's S7CommPlus dissector and thomas-v2/S7CommPlusDriver.
    """

    ERROR = 0x04B1
    EXPLORE = 0x04BB
    CREATE_OBJECT = 0x04CA
    DELETE_OBJECT = 0x04D4
    SET_VARIABLE = 0x04F2
    GET_VARIABLE = 0x04FC  # Only in old S7-1200 firmware
    ADD_LINK = 0x0506
    REMOVE_LINK = 0x051A
    GET_LINK = 0x0524
    SET_MULTI_VARIABLES = 0x0542
    GET_MULTI_VARIABLES = 0x054C
    BEGIN_SEQUENCE = 0x0556
    END_SEQUENCE = 0x0560
    INVOKE = 0x056B
    SET_VAR_SUBSTREAMED = 0x057C
    GET_VAR_SUBSTREAMED = 0x0586
    GET_VARIABLES_ADDRESS = 0x0590
    ABORT = 0x059A
    ERROR2 = 0x05A9
    INIT_SSL = 0x05B3
    # The Notify function (1326) is the server-initiated counterpart of the
    # subscription SetVariable credit: it frames a notification's response
    # bookkeeping. It shares its opcode byte with Opcode.NOTIFICATION.
    NOTIFY = 0x052E


class ElementID(IntEnum):
    """Tag IDs used in the object serialization format.

    S7CommPlus uses a tagged object model where data is structured as
    nested objects with attributes, similar to TLV encoding.
    Values 0xA1-0xAC match the serialization tag table in Wireshark's
    S7CommPlus dissector.
    """

    START_OF_OBJECT = 0xA1
    TERMINATING_OBJECT = 0xA2
    ATTRIBUTE = 0xA3
    RELATION = 0xA4
    ERROR = 0xA5
    INCLUDE_OBJECT = 0xA6
    START_OF_TAG_DESCRIPTION = 0xA7
    TERMINATING_TAG_DESCRIPTION = 0xA8
    LINK_NAMESPACE = 0xA9
    TYPE_MICRO_INFO = 0xAB
    TYPE_MICRO_NAMES = 0xAC
    # Aliases for the type-metadata list tags above, retained because the
    # tag_browser/typeinfo parsers and their tests refer to them by these names.
    VARTYPE_LIST = TYPE_MICRO_INFO
    VARNAME_LIST = TYPE_MICRO_NAMES


class ObjectId(IntEnum):
    """Well-known object IDs used in session establishment.

    Reference: thomas-v2/S7CommPlusDriver/Core/Ids.cs
    """

    NONE = 0
    GET_NEW_RID_ON_SERVER = 211
    CLASS_SUBSCRIPTIONS = 255
    CLASS_SERVER_SESSION_CONTAINER = 284
    OBJECT_SERVER_SESSION_CONTAINER = 285
    CLASS_SERVER_SESSION = 287
    OBJECT_NULL_SERVER_SESSION = 288
    SERVER_SESSION_CLIENT_RID = 300
    SERVER_SESSION_VERSION = 306


# Default TSAP for S7CommPlus connections
# The remote TSAP is the ASCII string "SIMATIC-ROOT-HMI" (16 bytes)
S7COMMPLUS_LOCAL_TSAP = 0x0600
S7COMMPLUS_REMOTE_TSAP = b"SIMATIC-ROOT-HMI"


class ConnectionType(IntEnum):
    """COTP called-TSAP identities an S7CommPlus client can present.

    S7CommPlus replaces the classic numeric rack/slot TSAPs with ASCII names
    for the client role. The default ``HMI`` identity is what this library has
    always used; ``ES``/``PG`` are offered so a caller can present a different
    role, which may matter on firmware that treats roles differently (not
    verified against a PLC).

    Reference: Wireshark S7CommPlus dissector (TSAP strings) and
    thomas-v2/S7CommPlusDriver.
    """

    HMI = 0  # HMI/SCADA-style data client (default)
    ES = 1  # Engineering station (TIA Portal style)
    PG = 2  # Programming device


_CONNECTION_TYPE_REMOTE_TSAPS: dict[int, bytes] = {
    ConnectionType.HMI: b"SIMATIC-ROOT-HMI",
    ConnectionType.ES: b"SIMATIC-ROOT-ES",
    ConnectionType.PG: b"SIMATIC-ROOT-PG",
}


def remote_tsap_for_connection_type(connection_type: int | str | None) -> bytes:
    """Return the COTP called TSAP for a connection type.

    Args:
        connection_type: A ``ConnectionType`` member, one of the case-
            insensitive names ``"hmi"``, ``"es"``, ``"pg"``, or ``None`` for
            the default ``"hmi"``.

    Raises:
        ValueError: If the connection type is not recognized.
    """
    if connection_type is None:
        return S7COMMPLUS_REMOTE_TSAP
    if isinstance(connection_type, str):
        try:
            connection_type = ConnectionType[connection_type.strip().upper()]
        except KeyError:
            raise ValueError(f"Unknown connection type {connection_type!r}; expected one of 'hmi', 'es', 'pg'") from None
    elif isinstance(connection_type, bool) or not isinstance(connection_type, int):
        # bool is an int subclass, so True/False would otherwise silently
        # select ES/HMI.
        raise ValueError(f"Unknown connection type {connection_type!r}; expected one of 'hmi', 'es', 'pg'")
    tsap = _CONNECTION_TYPE_REMOTE_TSAPS.get(int(connection_type))
    if tsap is None:
        raise ValueError(f"Unknown connection type {connection_type!r}; expected one of 'hmi', 'es', 'pg'")
    return tsap


class DataType(IntEnum):
    """S7CommPlus wire data types.

    These identify how values are encoded on the wire in the S7CommPlus
    protocol. Note: these differ from the Softdatatype IDs used for
    PLC variable type metadata.
    """

    NULL = 0x00
    BOOL = 0x01
    USINT = 0x02
    UINT = 0x03
    UDINT = 0x04
    ULINT = 0x05
    SINT = 0x06
    INT = 0x07
    DINT = 0x08
    LINT = 0x09
    BYTE = 0x0A
    WORD = 0x0B
    DWORD = 0x0C
    LWORD = 0x0D
    REAL = 0x0E
    LREAL = 0x0F
    TIMESTAMP = 0x10
    TIMESPAN = 0x11
    RID = 0x12
    AID = 0x13
    BLOB = 0x14
    WSTRING = 0x15
    VARIANT = 0x16
    STRUCT = 0x17
    S7STRING = 0x19


class Ids(IntEnum):
    """Well-known IDs for S7CommPlus protocol structures.

    Reference: thomas-v2/S7CommPlusDriver/Core/Ids.cs
    """

    # Data block access sub-areas
    DB_VALUE_ACTUAL = 2550
    # Symbolic (LID-based) access to controller areas (I/Q/M). The previous value
    # 2551 was wrong: 2551 is DB_InitialChanged, not a controller-area sub-area, so
    # the PLC rejected every I/Q/M symbolic read/write. ControllerArea_ValueActual
    # is 3736 (0xE98). Ref: thomas-v2/S7CommPlusDriver/Core/Ids.cs.
    CONTROLLER_AREA_VALUE_ACTUAL = 3736

    # SecurityKey struct IDs (from tkh-software/s7plus.net S7Ids.cs)
    STRUCT_SECURITY_KEY = 1800
    SECURITY_KEY_ID = 1825
    SESSION_KEY = 1830

    # ObjectQualifier structure IDs
    OBJECT_QUALIFIER = 1256
    PARENT_RID = 1257
    COMPOSITION_AID = 1258
    KEY_QUALIFIER = 1259

    # Native object RIDs for memory areas
    NATIVE_THE_I_AREA_RID = 80
    NATIVE_THE_Q_AREA_RID = 81
    NATIVE_THE_M_AREA_RID = 82
    NATIVE_THE_S7_COUNTERS_RID = 83
    NATIVE_THE_S7_TIMERS_RID = 84

    # Native object RIDs for EXPLORE
    NATIVE_THE_PLC_PROGRAM_RID = 3
    NATIVE_THE_ALARM_SUBSYSTEM_RID = 8
    NATIVE_THE_CPU_EXEC_UNIT_RID = 52

    # Remaining native-object roots under the AS root (RID 1). Useful as
    # EXPLORE starting points beyond the three above: the hardware
    # configuration tree, the folder/log containers, and the CPU objects.
    # Source: TIA Portal session captures (CreateObject/EXPLORE responses);
    # Ids.cs only defines RIDs 3, 8, 52 and 80-84. Not verified against a
    # live PLC. RID 35 is omitted: sources disagree on its name.
    NATIVE_THE_AS_ROOT_RID = 1
    NATIVE_THE_HW_CONFIGURATION_RID = 2
    NATIVE_THE_FOLDERS_RID = 4
    NATIVE_THE_LOGS_RID = 5
    NATIVE_THE_SW_EVENTS_RID = 10
    NATIVE_THE_TIS_SUBSYSTEM_RID = 11
    NATIVE_THE_STATION_CONFIGURATION_RID = 30
    NATIVE_THE_CPU_RID = 48
    NATIVE_THE_CPU_COMMON_RID = 50
    NATIVE_THE_CARD_READER_WRITER_RID = 51
    NATIVE_THE_WEB_SERVER_RID = 53
    NATIVE_THE_CPU_DISPLAY_RID = 54

    # Object attributes for EXPLORE responses
    OBJECT_VARIABLE_TYPE_NAME = 233
    BLOCK_BLOCK_NUMBER = 2521
    DATA_INTERFACE_INTERFACE_DESCRIPTION = 2544
    DATA_INTERFACE_LINE_COMMENTS = 2546
    AS_OBJECT_ES_COMMENT = 4288
    # Cycle-load values (see object_model.py); 1/7 in a hardware RUN capture and
    # 0/0 in STOP, but 0/8 and 0/10 in RUN on PLCSIM Advanced, so they are only a
    # fallback for get_cpu_state() when the operating-state code is absent.
    CPU_EXEC_UNIT_EXECUTING = 8064  # 0x1F80
    CPU_EXEC_UNIT_OPERATING_MODE = 8065  # 0x1F81
    # CPUexecUnit operating state: a Struct-typed attribute (0x8BD) with struct
    # id 0xD99, whose DINT member OperatingState (0xD9E) holds the state code.
    # Source: three EXPLORE replies of theCPUexecUnit (RID 52) captured on
    # PLCSIM Advanced V8.0, CPU 1511 FW V2.9, in RUN and STOP
    # (tests/fixtures/plcsim_cpu_exec_unit_20261008.py); all three carry struct
    # id 0xD99. Not yet seen on real hardware. The
    # writable counterpart OperatingStateREQ (0x877) takes the
    # OperatingStateRequest values. Names: thomas-v2/S7CommPlusDriver/Core/Ids.cs
    # (CPUexecUnit.*)
    CPU_EXEC_UNIT_OPERATING_STATE_STRUCT = 0x8BD
    CPU_EXEC_UNIT_OPERATING_STATE_STRUCT_ID = 0xD99
    CPU_EXEC_UNIT_OPERATING_STATE = 0xD9E
    CPU_EXEC_UNIT_OPERATING_STATE_REQ = 0x877

    # Block object attributes (ClassId Block = 0x9EA). Reported by EXPLORE for
    # program blocks; the know-how flag explains a block whose tag tree cannot
    # be browsed. Source: TIA Portal EXPLORE captures; Ids.cs defines only
    # Block_BlockNumber (2521). Not verified against a live PLC.
    BLOCK_BLOCKNUMBER = 0x9D9
    BLOCK_BLOCK_LANGUAGE = 0x9DA
    BLOCK_KNOWHOW_PROTECTED = 0x9DC
    BLOCK_UNLINKED = 0x9DF
    BLOCK_CRC = 0x9E4
    # Struct 0xD77 the KnowhowProtected attribute carries: Mode (BITSET16) and
    # Password (byte array).
    KNOWHOW_PROTECTION_STRUCT = 0xD77
    KNOWHOW_PROTECTION_MODE = 0xD78

    # Type info classes
    CLASS_TYPE_INFO = 511
    CLASS_OMS_TYPE_INFO_CONTAINER = 534
    OBJECT_OMS_TYPE_INFO_CONTAINER = 537
    PLC_PROGRAM_CLASS_RID = 2520
    DB_CLASS_RID = 2574  # ClassId of a DataBlock object in an EXPLORE response

    # Subscription classes (for data change notifications)
    CLASS_SUBSCRIPTIONS = 255
    CLASS_SUBSCRIPTION = 1001
    SUBSCRIPTION_MISSED_SENDINGS = 1002
    SUBSCRIPTION_SUBSYSTEM_ERROR = 1003
    SUBSCRIPTION_ROUTE_MODE = 1040
    SUBSCRIPTION_CYCLE_TIME = 1049
    SUBSCRIPTION_ACTIVE = 1041
    SUBSCRIPTION_CREDIT_LIMIT = 1053
    SUBSCRIPTION_REFERENCE_LIST = 1048
    SUBSCRIPTION_FUNCTION_CLASS_ID = 1082
    SUBSCRIPTION_REFERENCE_TRIGGER_MODE = 1005
    SUBSCRIPTION_DELAY_TIME = 1050
    SUBSCRIPTION_DISABLED = 1051
    SUBSCRIPTION_COUNT = 1052
    SUBSCRIPTION_TICKS = 1054

    # Alarm subscription
    ALARM_SUBSCRIPTION_REF_CLASS_RID = 2662
    ALARM_SUBSCRIPTION_REF_ALARM_DOMAIN = 2659
    ALARM_SUBSCRIPTION_REF_ITS_ALARM_SUBSYSTEM = 2660
    ALARM_SUBSCRIPTION_REF_ALARM_DOMAIN_FILTER = 7731
    ALARM_SUBSCRIPTION_REF_SEND_TEXTS = 8173
    ALARM_SUBSCRIPTION_REF_TEXT_LANGUAGES = 8181

    # Alarm objects and text libraries
    ALARM_SUBSYSTEM_UPDATE_RELEVANT_DAI = 2667
    ALARM_DAI_CPU_ALARM_ID = 2670
    ALARM_DAI_ALL_STATES_INFO = 2671
    ALARM_DAI_DOMAIN = 2672
    ALARM_DAI_COMING = 2673
    ALARM_DAI_GOING = 2677
    ALARM_DAI_CLASS_RID = 2681
    ALARM_DAI_TEXTS = 2715
    ALARM_DAI_MESSAGE_TYPE = 4079
    ALARM_DAI_HMI_INFO = 7813
    ALARM_DAI_SEQUENCE_COUNTER = 7917

    # Session's effective protection level, readable via GetVarSubStreamed
    EFFECTIVE_PROTECTION_LEVEL = 1842
    ACTIVE_PROTECTION_LEVEL = 1843

    # ServerSessionVersion (struct 314) elements. 315/319 are what the client
    # reads (protocol version, device PAOM string); 316-318 and 320 are the
    # project-side counterparts a PLC may also send.
    # Source: 306 and 319 are thomas-v2/S7CommPlusDriver/Core/Ids.cs
    # (ServerSessionVersion, LID_SessionVersionSystemPAOMString). The struct
    # id 314 and elements 315-318, 320 come from TIA Portal session captures
    # (CreateObject responses); not verified against a live PLC.
    SESSION_VERSION_STRUCT = 314
    SESSION_VERSION_SYSTEM_OMS = 315
    SESSION_VERSION_PROJECT_OMS = 316
    SESSION_VERSION_SYSTEM_PAOM = 317
    SESSION_VERSION_PROJECT_PAOM = 318
    SESSION_VERSION_SYSTEM_PAOM_STRING = 319
    SESSION_VERSION_PROJECT_PAOM_STRING = 320

    # ServerSession attributes reported in the CreateObject response object.
    # Source: TIA Portal session captures (CreateObject responses); Ids.cs
    # only defines 300, 303, 304, 306. Not verified against a live PLC.
    SERVER_SESSION_CLIENT_ID = 289
    SERVER_SESSION_USER = 296
    SERVER_SESSION_APPLICATION = 297
    SERVER_SESSION_HOST = 298
    SERVER_SESSION_ROLE = 299
    SERVER_SESSION_TIMEOUT = 302
    SERVER_SESSION_ROLES = 305
    CLIENT_SESSION_PASSWORD = 309
    CLIENT_SESSION_LEGITIMATED = 310

    # Struct and element IDs of the encrypted new-mode legitimation payload
    LEGITIMATION_PAYLOAD_STRUCT = 40400
    LEGITIMATION_PAYLOAD_TYPE = 40401
    LEGITIMATION_PAYLOAD_USERNAME = 40402
    LEGITIMATION_PAYLOAD_PASSWORD = 40403

    # DB AccessArea base (add DB number to get area ID)
    DB_ACCESS_AREA_BASE = 0x8A0E0000

    # Marker for raw/absolute access to non-optimized data. The address path is
    # this marker followed by a zero-based byte offset and byte size.
    LID_OMS_STB_CLASSIC_BLOB = 3


# Function codes that use the READ IntegrityId counter (V2+)
READ_FUNCTION_CODES: frozenset[int] = frozenset(
    {
        FunctionCode.GET_MULTI_VARIABLES,
        FunctionCode.EXPLORE,
        FunctionCode.GET_VAR_SUBSTREAMED,
        FunctionCode.GET_LINK,
        FunctionCode.GET_VARIABLE,
        FunctionCode.GET_VARIABLES_ADDRESS,
    }
)

# Function codes whose requests carry transport flags 0x34. The reference sets
# this per request class rather than by read/write, so it is a different split
# than READ_FUNCTION_CODES: the writes SetVariable, SetMultiVariables and
# DeleteObject use 0x34 too. Only CreateObject (0x36) and InitSSL (0x30) differ,
# and a session-setup CreateObject sent with 0x34 makes the PLC reset the
# connection. Subscription and alarm CreateObjects are the documented exception:
# the reference overrides those to 0x34.
#
# Reference: TransportFlags in thomas-v2/S7CommPlusDriver/Core/*Request.cs
FLAGS_34_FUNCTION_CODES: frozenset[int] = frozenset(
    {
        FunctionCode.DELETE_OBJECT,
        FunctionCode.EXPLORE,
        FunctionCode.GET_MULTI_VARIABLES,
        FunctionCode.GET_VAR_SUBSTREAMED,
        FunctionCode.SET_MULTI_VARIABLES,
        FunctionCode.SET_VARIABLE,
    }
)


class AccessLevel(IntEnum):
    """Protection levels reported by `Ids.EFFECTIVE_PROTECTION_LEVEL`.

    Lower is more privileged. A successful legitimation lowers the level; the
    level reached depends on which password was configured for which role, so
    it does not necessarily become `FULL_ACCESS`.

    `NONE` is not in the C# reference; PLCs with no protection configured
    report it.

    Reference: thomas-v2/S7CommPlusDriver/Legitimation/AccessLevel.cs
    """

    NONE = 0
    FULL_ACCESS = 1
    READ_ACCESS = 2
    HMI_ACCESS = 3
    NO_ACCESS = 4


class LegitimationType(IntEnum):
    """Legitimation mode.

    Reference: thomas-v2/S7CommPlusDriver/Legitimation/LegitimationType.cs
    """

    LEGACY = 1
    NEW = 2


class LegitimationId(IntEnum):
    """Legitimation IDs used in password authentication (V2+).

    Reference: thomas-v2/S7CommPlusDriver
    """

    SERVER_SESSION_REQUEST = 303
    SERVER_SESSION_RESPONSE = 304
    # V2 session-setup legitimation, written alongside ServerSessionVersion
    # in the same SetMultiVariables on V1-initial S7-1200 firmware. Distinct
    # from LEGITIMATE (1846) which is the password-auth challenge response.
    SESSION_SETUP_LEGITIMATION = 1830
    LEGITIMATE = 1846


class BlockLanguage(IntEnum):
    """Programming language of a program block (attribute 0x9DA).

    Source: TIA Portal block-property captures; the codes are the SIMATIC
    block-language identifiers. Not verified against a live PLC.
    """

    UNDEF = 0
    STL = 1
    LAD = 2
    FBD = 3
    SCL = 4
    DB = 5
    GRAPH = 6
    SDB = 7
    CPU_DB = 8
    CPU_SDB = 17
    C_FOR_S7 = 21
    HIGRAPH = 22
    CFC = 23
    SFC = 24
    S7_PDIAG = 29
    RSE = 31
    F_STL = 32
    F_LAD = 33
    F_FBD = 34
    F_DB = 35
    F_CALL = 36
    TECHNO_DB = 37
    F_LAD_LIB = 38
    F_FDB_LIB = 39
    CLASSIC_ENCRYPTION = 41
    FCP = 50
    LAD_IEC = 100
    FBD_IEC = 101
    FLD = 102
    MOTION_DB = 201
    GRAPH_ACTIONS = 300
    GRAPH_SEQUENCE = 301
    GRAPH_ADDINFOS = 303
    GRAPH_PLUS = 310
    MC7PLUS = 400


def block_language_name(code: int) -> str:
    """Return the conventional name of a block language code, ``"Undef"`` for 0.

    Unknown codes return a ``"language <n>"`` spelling rather than raising, so
    an unrecognized value from newer firmware degrades to a readable string.
    """
    try:
        return BlockLanguage(code).name
    except ValueError:
        return f"language {code}"


class AttributeFlags(IntFlag):
    """Access flags of an object attribute in the S7CommPlus object model.

    Every attribute carries a bitmask describing who may read or write it and
    under which conditions. The interesting ones for a client: whether a write
    needs legitimation first, whether the attribute is read-only for clients,
    and whether it may change while the CPU runs.

    Source: TIA Portal attribute-metadata captures; Ids.cs defines no
    attribute flags. 23 nonzero flags plus the zero ``TO_BE_CONFIGURED``
    value. Not verified against a live PLC.
    """

    TO_BE_CONFIGURED = 0
    APPLICATION_READABLE = 0x00000001
    APPLICATION_WRITABLE = 0x00000002
    IS_IN = 0x00000004
    IS_OUT = 0x00000008
    CORE = 0x00000010
    PERSISTENT = 0x00000020
    BL = 0x00000040
    AS_EVALUATION_REQUIRED = 0x00000100
    SEPARATE_LOAD_MEMORY_FILE_ALLOWED = 0x00000200
    CLIENT_READONLY = 0x00000400
    SERVER_ONLY = 0x00000800
    CHANGEABLE_IN_RUN = 0x00002000
    NEEDS_LEGITIMATION = 0x00004000
    NORMAL_ACCESS = 0x00008000
    STREAMING = 0x00010000
    IS_QUALIFIER = 0x00040000
    HMI_ACCESSIBLE = 0x00100000
    HMI_CACHED = 0x00200000
    HMI_READONLY = 0x00400000
    HMI_VISIBLE = 0x00800000
    PLAIN_MEMBER_CLASSIC = 0x01000000
    PLAIN_MEMBER_RETAIN = 0x02000000
    IS_HOST_RELEVANT = 0x08000000


def attribute_flags_description(flags: int) -> str:
    """Describe an attribute-flags bitmask as a comma-separated name list.

    Known bits decode to their names; unknown bits render as ``bit 0x...`` so
    a flags value from newer firmware stays readable.

    >>> attribute_flags_description(0x4000)
    'needs_legitimation'
    """
    value = AttributeFlags(flags)
    names = [name.lower() for member in AttributeFlags if member.value and value & member for name in [str(member.name)]]
    unknown = flags & ~_KNOWN_ATTRIBUTE_FLAG_BITS
    if unknown:
        names.append(f"bit 0x{unknown:X}")
    return ", ".join(names) if names else "none"


_KNOWN_ATTRIBUTE_FLAG_BITS = functools.reduce(int.__or__, (int(member.value) for member in AttributeFlags))


# --- INVOKE method identifiers -------------------------------------------------
#
# INVOKE calls a method on a PLC object: TargetObjectId (RID), TargetMethodId,
# then sparse in/inout argument arrays. The method ids below are the ones the
# protocol's method surface defines. A RemoteFileAccessManager instance is not
# a fixed RID: the client creates the object and the PLC assigns the RID, so
# callers track the CreateObject response.
#
# Source: TIA Portal method-call captures (file transfer, runtime update and
# full-download sessions) plus the protocol's own method naming; Ids.cs
# defines none of these. ResolveAddressRemote's RID was seen in a
# resolve-address exchange. Not verified against a live PLC.

#: RemoteFileAccessManager methods (on a created RemoteFileAccessManager object).
REMOTE_FILE_ACCESS_MANAGER_METHODS: dict[int, str] = {
    1: "Init",
    2: "OpenFile",
    3: "ReadFile",
    4: "WriteFile",
    5: "CloseFile",
    6: "OpenDir",
    7: "ReadDir",
    8: "CloseDir",
    9: "DeleteFile",
    10: "CreateDir",
    11: "DeleteDir",
    12: "GetFileInfo",
    13: "RenameFile",
    15: "Reserve",
    16: "Unreserve",
}

#: HMI/RuntimeUpdate service methods (fixed method ids on their service objects).
HMI_METHODS: dict[int, str] = {
    18667: "AddonObject.CheckCompat",
    18827: "RuntimeUpdateService.BeginRuntimeUpdate",
    18829: "RuntimeUpdateService.FinishRuntimeUpdate",
    18878: "RuntimeUpdateService.UninstallAddon",
    15000009: "DownloadService.PreFullDownload",
    15000011: "DownloadService.PostFullDownload",
    15000013: "DownloadService.CheckFullDownload",
    15000016: "DownloadService.ActivateDownload",
    15000019: "DownloadService.AbortFullDownload",
    15000035: "ScsProject.GetFullDownloadServiceRid",
    15000039: "ProjectManager.GetScsProject",
}

# RID and method id of the address-resolution method: INVOKE(1387, 1387)
# resolves a symbolic name to its access address without enumerating the
# object tree, an alternative to the GetVariablesAddress function.
RESOLVE_ADDRESS_REMOTE_RID = 1387
RESOLVE_ADDRESS_REMOTE_METHOD = 1387


def invoke_method_name(
    target_object_id: int,
    target_method_id: int,
    remote_file_access_manager_rids: frozenset[int] | set[int] | None = None,
) -> str:
    """Return a readable name for an INVOKE (RID, method id) pair.

    The address resolver is identified by its well-known RID; service methods
    by their fixed ids. RemoteFileAccessManager methods resolve only when the
    caller says the object is a file manager — its RID is assigned per session
    by the PLC, so the caller passes the RID it received from CreateObject
    (one or more, as ``remote_file_access_manager_rids``). Without that
    knowledge a small method id is just a small method id, and the pair
    degrades to a neutral ``"method 0x..."`` spelling rather than being
    mislabelled as a file-access call.
    """
    if target_object_id == RESOLVE_ADDRESS_REMOTE_RID:
        return "ResolveAddressRemote"
    if target_method_id in HMI_METHODS:
        return HMI_METHODS[target_method_id]
    if remote_file_access_manager_rids and target_object_id in remote_file_access_manager_rids:
        if target_method_id in REMOTE_FILE_ACCESS_MANAGER_METHODS:
            return f"RemoteFileAccessManager.{REMOTE_FILE_ACCESS_MANAGER_METHODS[target_method_id]}"
    return f"method 0x{target_method_id:X}"


class ServiceResult(IntEnum):
    """Result codes a PLC returns in place of 0 (success) for a service.

    S7CommPlus services answer with a 64-bit return value whose low bits
    carry one of these codes. Positive values are informational outcomes
    (the request still succeeded); negative values are failures. The
    numeric values also appear in the low word of composite return values
    (error flag | error source | code), which is why a rejected request
    commonly shows up as a large value such as ``0x8318890001B3FFFE``
    (code -2 from source 0x19).

    Reference: Wireshark S7CommPlus dissector result-code table and
    thomas-v2/S7CommPlusDriver result handling.
    """

    # --- Legitimation outcomes (SetVariable on ServerSession) ---
    # A PLC may report that the session already carries a lower protection
    # level than the requested one, or was legitimated to a specific level.
    # All of these mean the legitimation itself succeeded.
    SESSION_PRE_LEGITIMIZED = 17
    SERVICE_LEGITIMATED_FOR_LEVEL1 = 33
    SERVICE_LEGITIMATED_FOR_LEVEL2 = 25
    SERVICE_LEGITIMATED_FOR_LEVEL3 = 26
    # The PLC answered the challenge with the wrong password.
    SERVICE_SESSION_DELEGITIMATED = 22
    SERVICE_SESSION_DELEGITIMATED_LEGACY = -118

    # --- Common service outcomes ---
    SERVICE_IGNORED = 18
    SERVICE_EXECUTED_WITH_PARTIAL_ERROR = 19
    SERVICE_SUBSCRIPTION_TOO_MANY_NOTIFIES = 21
    SERVICE_SUBSCRIPTION_DISABLED = 24
    SERVICE_TRANSACTION_ABORTED = 34
    TEMPORARILY_OUT_OF_RESOURCES = 37
    LEGITIM_LEVEL_CURRENTLY_DISABLED = 38
    END_OF_FILE = 23
    BLOB_REALLOCATED = 35
    BLOB_END_REACHED = 40

    # --- Negative failure codes (low word of a composite return value) ---
    OK = 0
    INVALID_VALUE_TYPE = -2
    INVALID_ARGUMENT_VALUE = -3
    NOT_ENOUGH_MEMORY = -4
    UNKNOWN_ERROR = -1


def service_result_code(return_value: int) -> int:
    """Extract the ServiceResult code from a composite return value.

    A composite return value packs ``error flag | error source | code`` into
    the upper bits with the code's sign-extended low word at the bottom:

    - a plain small negative number is already the code (legacy encoding),
    - a value with the top bit set has its low 16 bits sign-extended, whether
      it arrives as an unsigned 64-bit value or as its negative Python int.

    >>> service_result_code(0x8318890001B3FFFE)
    -2
    >>> service_result_code(-2)
    -2
    >>> service_result_code(-9000293222178357250)  # the same value, negative
    -2
    >>> service_result_code(0)
    0
    """
    if -(1 << 16) < return_value < 0:
        return return_value  # a plain legacy code, not a composite
    low = return_value & 0xFFFF
    return low - 0x10000 if low & 0x8000 else low


class OperatingStateRequest(IntEnum):
    """Values written to CPUexecUnit.OperatingStateREQ (attribute 0x877).

    Source: TIA Portal captures of operating-state requests. Unverified
    against a real PLC — see #8. Any future write path must be opt-in and
    clearly named, per that issue.
    """

    STOP = 1
    RESET_RETENTIVE = 2
    RUN = 3
    RUN_REDUNDANT = 4


# Values of the read-only OperatingState member (0xD9E) seen in TIA Portal
# captures and in EXPLORE replies from PLCSIM Advanced (CPU 1511, FW V2.9):
# 4 while stopped, 8 while running. Not yet confirmed on real hardware, and the
# STARTUP/HOLD-family values in between are not pinned.
OPERATING_STATE_STOP_OBSERVED = 4
OPERATING_STATE_RUN_OBSERVED = 8


class SoftDataType(IntEnum):
    """PLC soft data types (used in variable metadata / tag descriptions).

    These correspond to the data types as they appear in the PLC's symbol
    table and are used for symbolic access to optimized data blocks.
    """

    VOID = 0
    BOOL = 1
    BYTE = 2
    CHAR = 3
    WORD = 4
    INT = 5
    DWORD = 6
    DINT = 7
    REAL = 8
    DATE = 9
    TIME_OF_DAY = 10
    TIME = 11
    S5TIME = 12
    DATE_AND_TIME = 14
    ARRAY = 16
    STRUCT = 17
    STRING = 19
    POINTER = 20
    ANY = 22
    BLOCK_FB = 23
    BLOCK_FC = 24
    BLOCK_DB = 25
    BLOCK_SDB = 26
    COUNTER = 28
    TIMER = 29
    IEC_COUNTER = 30
    IEC_TIMER = 31
    BLOCK_SFB = 32
    BLOCK_SFC = 33
    BLOCK_OB = 36
    BLOCK_UDT = 37
    LREAL = 48
    ULINT = 49
    LINT = 50
    LWORD = 51
    USINT = 52
    UINT = 53
    UDINT = 54
    SINT = 55
    WCHAR = 61
    WSTRING = 62
    VARIANT = 63
    LTIME = 64
    LTOD = 65
    LDT = 66
    DTL = 67


class ErrorSource(IntEnum):
    """Subsystems that a composite return value can name as the error source.

    A rejected service reports a composite 64-bit value whose low word is the
    `ServiceResult` code and whose upper bits identify the reporting
    subsystem. The exact bit layout of the upper bits varies by firmware and
    is not decoded here; the enum documents the source identifiers so a
    decoded value can be named once the layout is confirmed against a capture.

    Reference: Wireshark S7CommPlus dissector error-source table and
    thomas-v2/S7CommPlusDriver result handling.
    """

    OBJECT_MANAGEMENT_SYSTEM = 0
    OPERATING_STATE_CONTROL = 1
    LOAD_MEMORY_CONTROL = 3
    WORKING_MEMORY_CONTROL = 4
    TEST_DEBUG_SYSTEM = 7
    ALARMING_SYSTEM = 8
    ONBOARD_COMPILER = 13
    KERNEL = 14
    GENERAL_AS_OBJECT_MODEL_ERRORS = 25
    GENERAL_HARDWARE_CONFIGURATION_ERRORS = 26
    FILESYSTEM = 32
    COMMUNICATION_SYSTEM = 33
    EXECUTION_LEVEL_SYSTEM = 64
    T_BLOCKS = 91
    IE_CONFIG = 92
