"""
S7CommPlus protocol constants and types.

Defines the protocol framing, opcodes, function codes, data types,
element IDs, and other constants needed for S7CommPlus communication.

Reference: thomas-v2/S7CommPlusDriver (C#, LGPL-3.0)
Reference: Wireshark S7CommPlus dissector
"""

import functools
import warnings
from dataclasses import dataclass
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
    # VariableTypeStructModificationTime: when a type-info object's layout last
    # changed. Seen on PLCSIM Advanced V8.0 (CPU 1511, FW V2.9), as
    # ``a3 84 11 00 05 ...`` (attribute 529, a ULInt) in the EXPLORE response
    # pinned by tests/test_s7_stale_tags.py, and in a read-only probe of a real
    # CPU 1215C DC/DC/DC (FW V4.2): 42 of its 54 data blocks' type-info objects
    # reported it, stable on repeated reads and equal in the browse and a
    # filtered EXPLORE. That it changes on a download is not verified on hardware.
    # The name is single-source: it follows the attribute-id table of Wireshark's
    # S7CommPlus dissector (packet-s7comm_plus.c), at an unverified line and version.
    VARIABLE_TYPE_STRUCT_MODIFICATION_TIME = 529
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
    # id 0xD99. On hardware, a read-only probe of a CPU 1215C DC/DC/DC (FW V4.2)
    # read the same struct id with code 8 in RUN; STOP is unverified there. The
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
    # Block_BlockNumber (2521). BlockLanguage and AutoNumbering (0 on blocks
    # numbered by hand) were seen on an S7-1500 FW V2.9; the others are not
    # verified against a live PLC.
    BLOCK_BLOCK_NUMBER = 0x9D9
    BLOCK_AUTO_NUMBERING = 0x9DA
    BLOCK_BLOCK_LANGUAGE = 0x9DB
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
    FB_CLASS_RID = 2578
    FC_CLASS_RID = 2579
    CYCLIC_OB_CLASS_RID = 2640
    PROGRAM_CYCLE_OB_CLASS_RID = 2647
    UDT_CLASS_RID = 3932
    PLC_PROGRAM_CHANGE_CLASS_RID = 8040

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
    """Programming language of a program block (attribute 0x9DB).

    Source: TIA Portal block-property captures; the codes are the SIMATIC
    block-language identifiers. Only DB (5) is verified, on an S7-1500 FW V2.9.
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
    carry one of these codes (see `ReturnValue` for the whole layout).
    Positive values are informational outcomes (the request still
    succeeded); negative values are failures. A rejected request therefore
    shows up as a large value such as ``0x8318890001B3FFFE``: code -2 in the
    low word, with the failure flag and generic category in the upper bits.

    Members are ordered by value.
    """

    PMS_MISMATCH = -522
    SERVICE_PWD_EXPIRED = -521
    SERVICE_TLS_ONLY = -520
    SERVICE_NO_TLS = -519
    TLS_INTERFACE_MISSING = -518
    TLS_VERIFICATION_FAILED = -517
    OPEN_SSL = -516
    REFERENCED_OBJECT_DELETED = -515
    WRONG_ENUM_TYPE = -514
    CONCURRENT_TRANSACTION_RUNNING = -513
    MULTI_ES_INCOMPATIBLE_OTHER_ES_VERSION = -512
    MULTI_ES_LIMIT_EXCEEDED = -511
    MULTI_ES_CONFLICT = -510
    STREAMING_ERROR = -509
    NOT_ALLOWED_WITH_STREAMING = -508
    NO_SUPPORT_FOR_TLS = -507
    STOPPING_TLS_FAILED = -506
    START_TLS_FAILED = -505
    PASSWORD_ALREADY_USED = -504
    SPACE_SIGN_ONLY_HASH = -503
    INVALID_TYPE_INFO_FORMAT = -502
    SYSTEM_LIMIT_EXCEEDED = -501
    WORKS_FOR_PROXY_OBJECTS_ONLY = -409
    TEXT_LIB_BUFFER_OVERFLOW = -408
    TEXT_LIB_CURRENTLY_NOT_AVAILABLE = -407
    INVALID_SEARCH_MODE = -406
    TEXT_LIB_DUPLICATED_TEXT_ID = -405
    TEXT_LIB_NO_LIST_HEADER = -404
    TEXT_LIB_NOT_INITIALIZED = -403
    TEXT_LIB_INCONSISTENT_STRUCTURE = -402
    INVALID_COMPILER_ALIGNMENT = -401
    SSL_HANDSHAKE = -353
    SECURITY_DISCONNECT = -352
    INTEGRITY_ERROR = -351
    DS_INCOMPLETE_PREPARATION = -303
    DS_TARGET_LOST_UNEXPECTED = -302
    DS_INCONSISTANT_CONTAINER = -301
    DS_NOT_INITIALIZED = -300
    CONFIGURED_SIZE_INVALID = -280
    PLAIN_STRUCTURE_NEEDS_LITTLE_ENDIAN_DATA = -279
    PLAIN_STRUCTURE_NEEDS_BIG_ENDIAN_DATA = -278
    PLAIN_STRUCTURE_NEEDS_NENA_OFFSETS = -277
    PLAIN_STRUCTURE_NEEDS_CLASSIC_OFFSETS = -276
    NOT_ALLOWED_FOR_PERSISTENT_DATA = -275
    NO_DATA_PTR_AVAILABLE = -274
    TYPE_INFO_HIERARCHY_OVERFLOW = -273
    NO_OFFSET_PUBLISHED = -272
    VARIABLE_IS_OBSOLETE = -271
    NOT_OMS = -270
    STORE_DEFECT = -269
    INVALID_THREAD_CONTEXT = -268
    OBJECT_HAS_BEEN_DELETED = -267
    STORE_NOT_EXISTING = -266
    STORE_TRANSACTION_NOT_RUNNING = -265
    STORE_TRANSACTION_ALREADY_RUNNING = -264
    INVALID_STATE = -263
    DUPLICATE_QUALIFIER_VALUE = -262
    CBT_CONTAINER_NEEDED = -261
    NOT_CREATEABLE_BY_TRANSACTION = -260
    INVALID_TRANSACTION_STATE = -259
    INVALID_VERSION = -258
    VALUE_CONVERSION_NOT_POSSIBLE = -257
    INVALID_TYPE_INFO_MODIFICATION_TIME = -256
    INVALID_LID = -255
    TYPE_INFO_NOT_SET = -254
    ONLY_TYPE_INFO_ALLOWED = -253
    TYPE_INFO_INVALID_STRUCTURE_TYPE = -252
    STRUCT_NOT_AS_BLOB_ACCESSIBLE = -251
    WSTRING_NOT_SUPPORTED = -250
    CONSISTENCY_ASYNC_CALL_FAILED = -249
    ASYNC_CALL_FAILED = -248
    CALLBACK_MISSING = -247
    NULL_POINTER = -246
    STORE_REFUSED_BY_BL = -245
    STORE_IS_BUSY = -244
    STORE_HANDLER_NOT_FREE = -243
    FILE_FIND_ELEMENT = -242
    FILE_INVALID_FIND_STATE = -241
    STATE_INVALID_CASE = -240
    ASYNC_FILE_RUNNING = -239
    SOURCE_FILE_NOT_EXISTING = -238
    STORE_ALREADY_EXISTING = -237
    STORE_INVALID_HANDLE = -236
    VALUE_MISSING = -235
    SERIALIZER_REINIT_FAILED = -234
    STORE_BAD_INDEX = -233
    STORE_WRONG_FORMAT = -232
    STORE_INACTIVE = -231
    STORE_FORCE_STORE = -230
    FILE_UNLINK_ERROR = -227
    FILE_WRITE_ERROR = -226
    FILE_READ_ERROR = -225
    STORE_HAS_TRANSACTION_LOCK = -223
    START_TIMER_ERROR = -222
    INVALID_CONSISTENCY_ID = -221
    NOT_IN_CONSISTENCY = -220
    FILE_INVALID_ACCESS = -219
    DIRECTORY_REMOVE_ERROR = -218
    DIRECTORY_ALREADY_CLOSED = -217
    DIRECTORY_ALREADY_OPEN = -216
    FILE_NOT_FOUND = -215
    MESSAGE_BLOCK_INIT_ERROR = -214
    ASYNC_FILE_INSTANCE_IN_USE_ERROR = -213
    HAS_FILE_NAME_ERROR = -212
    NO_FILE_NAME = -211
    FILE_INNER_ERROR = -210
    DIRECTORY_CREATE_ERROR = -209
    DIRECTORY_OPEN_ERROR = -208
    DIRECTORY_CLOSE_ERROR = -207
    DIRECTORY_READ_ERROR = -206
    INVALID_OPEN_MODE = -205
    FILE_ALREADY_CLOSED = -204
    FILE_ALREADY_OPEN = -203
    FILE_CLOSE_ERROR = -202
    FILE_OPEN_ERROR = -201
    MODEL_INCONSISTENT = -171
    REDIRECTION_NOT_ALLOWED = -170
    REDIRECTION_CALLED_TWICE = -169
    TREE_READ_LOCKED = -168
    OBJECT_NOT_LOCKED = -167
    CHILD_ALREADY_LOCKED_FOR_DELETION = -166
    EXCLUSIVE_LOCKED_AGAINST_DELETION = -165
    LOCK_FOR_DELETION = -164
    LOCKING_LOOP_OVERFLOW = -163
    TREE_LOCKED_AGAINST_DELETION = -162
    WRONG_LOCK_FOR_DELETION_OBJECT = -161
    LOCKING_COUNTER_UNDERFLOW = -160
    LOCKING_COUNTER_OVERFLOW = -159
    CALLBACK_INTERFACE_IS_MISSING = -158
    CHILD_LOCKED = -157
    LOCKING_STRATEGY_ALREADY_IN_QUEUE = -156
    LOCKING_STRATEGY_NOT_IN_PROGRESS = -155
    EXCLUSIVE_LOCKED = -154
    LOCKING_STRATEGY_NOT_FOUND = -153
    LOCKING_STRATEGY_ALREADY_IN_PROGRESS = -152
    WRONG_LOCKING_STRATEGY = -151
    TREE_WRITE_LOCKED = -150
    SERVICE_COMM_FORMAT_DIFFERS_FROM_STORE_FORMAT = -136
    SERVICE_ABORTED = -135
    SERVICE_MULTI_ES_NOT_SUPPORTED = -134
    SERVICE_NOT_CHANGABLE_IN_ERROR_STATE = -133
    SERVICE_SUBSCRIPTION_IS_NOT_RUNNING = -132
    SERVICE_SUBSCRIPTION_PREPARE_SEQUENCE_ERROR = -131
    SERVICE_UNKNOWN_COM_FORMAT = -130
    SERVICE_OBJECT_SERIALIZATION_ERROR = -129
    SERVICE_TYPE_ALREADY_EXISTS = -128
    SERVICE_ASYNC_RMC_IMPOSSIBLE = -127
    SERVICE_WRONG_ARGUMENT_FORMAT = -126
    SERVICE_WRONG_NR_OF_ARGUMENTS = -125
    SERVICE_NOT_CHANGABLE_IN_RUN = -124
    SERVICE_REQUEST_SERIALIZATION_ERROR = -123
    SERVICE_NOTIFICATION_PARSING_ERROR = -122
    SERVICE_OBJECT_PARSING_ERROR = -121
    SERVICE_REQUEST_PARSING_ERROR = -120
    SERVICE_UNKNOWN_REQUEST = -119
    # The PLC answered the legitimation challenge with the wrong password (older firmware).
    SERVICE_SESSION_DELEGITIMATED_LEGACY = -118
    SERVICE_PENDING_REQUEST_NOT_FOUND = -117
    SERVICE_UNEXPECTED_STREAM = -116
    SERVICE_UNEXPECTED_RESPONSE = -115
    SERVICE_CANNOT_CREATE_REQUEST = -114
    SERVICE_TOO_MANY_SESSIONS = -113
    SERVICE_TOO_MANY_REQUESTS = -112
    SERVICE_TIMEOUT = -111
    SERVICE_NOT_OWNER = -110
    SERVICE_NOT_CONNECTED = -109
    SERVICE_NOT_AVAILABLE = -108
    SERVICE_NOT_ALLOWED = -107
    SERVICE_INVALID_SESSION = -106
    SERVICE_INVALID_OBJECT = -105
    SERVICE_INVALID_ADDRESS = -104
    SERVICE_FAILED_TO_DISCONNECT = -103
    SERVICE_DISCONNECTED = -102
    SERVICE_ACTIVATE_FAILED = -101
    SERVICE_ACCESS_DENIED = -100
    PERSISTENCE_NOT_AVAILABLE = -99
    NOT_PERSISTENT = -98
    VARIABLE_WITH_QUALIFIER = -97
    INVALID_OBJECT_WITH_QUALIFIER = -96
    NOT_IMPLEMENTED = -95
    OBJECT_IS_NOT_PASSIVE = -94
    OBJECT_ALREADY_IN_TREE = -93
    OBJECT_IS_ACTIVE = -92
    OBJECT_IS_PASSIVE = -91
    OBJECT_IS_MARKED_FOR_DELETION = -90
    DATA_IS_REFERENCED = -89
    INFO_NOT_AVAILABLE = -88
    OCB_MISSING = -87
    NO_DELETE_ALLOWED = -86
    STRUCT_ONLY_IN_DETAILS_ACCESSIBLE = -85
    VALUE_NOT_MOVEABLE = -84
    OCB_ALREADY_USED = -82
    AID_ALREADY_SET = -81
    DUPLICATE_AID = -80
    NO_PROXY_OBJECT_ALLOWED = -79
    ALLOCATOR_NOT_FOUND = -78
    OBJECT_FACTORY_NOT_FOUND = -77
    CANNOT_DELETE_NATIVE_OBJECT = -76
    VALUE_TIMEOUT = -75
    COMPOSITION_NOT_ALLOWED = -74
    ASYNC_BUT_CALLBACK_INTERFACE_NOT_FOUND = -73
    ELEMENT_IS_TRANSISTENT = -72
    HIERARCHY_OVERFLOW = -71
    INVALID_ASSOCIATION = -70
    QUALIFIER_NOT_SYNC = -69
    QUALIFIER_NOT_FOUND = -68
    INVALID_ROOT = -67
    HASH_INDEX_NOT_FOUND = -66
    ITERATOR_INTERFACE_NOT_FOUND = -65
    OBJECT_ALREADY_IN_ASSOCIATION = -64
    ASSOCIATION_NOT_FOUND = -63
    ASSOCIATION_NOT_QUALIFIED = -62
    INVALID_VALUE_RANGE = -61
    DUPLICATE_RID = -60
    LINK_INTERFACE_NOT_FOUND = -59
    ASYNC_ONLY = -58
    VARIABLE_TYPE_NOT_ALLOWED = -57
    VARIABLE_IS_SPECIFIC_ONLY = -56
    INVALID_COMPOSITION = -55
    NO_FREE_RID = -54
    BUFFER_OVERFLOW = -53
    DUPLICATE_LINK = -52
    OBJECT_IS_LOCKED = -51
    READ_ONLY_OBJECT = -50
    STRING_MUST_HAVE_HEX_CHARACTERS_ONLY = -49
    LINK_NOT_FOUND = -48
    INVALID_META_TYPE = -47
    OBJECT_IS_NOT_INSTANTIABLE = -46
    TYPE_INFO_MAX_COMPLEXITY_REACHED = -46
    CANNOT_CREATE_ABSTRACT_OBJECT = -45
    NO_SEPARATE_LOAD_MEMORY_FILE_ALLOWED = -44
    CREATE_CHILD_OBJECT_WITHIN_CREATE_CHILD_OBJECT = -43
    M_N_ASSOC_NOT_SUPPORTED = -42
    READ_ONLY_PROPERTY = -41
    DIRECTORY_NOT_FOUND = -40
    FILENAME_EXCED_RANGE = -39
    CLASS_NOT_ALLOWED = -38
    UNEXPECTED_ATTRIBUTE = -37
    NUMERIC_UNDERFLOW = -36
    NUMERIC_OVERFLOW = -35
    UNEXPECTED_TOKEN = -34
    BAD_CAST = -33
    INVALID_AID = -32
    INVALID_RID = -30
    OBJECT_EXISTS_WITH_SAME_ID = -29
    UNEXPECTED_FRAG_TYPE = -28
    UNEXPECTED_END_TAG = -27
    UNKNOWN_START_TAG = -26
    INVALID_TYPE_ID = -25
    INVALID_ID = -24
    WRITING_DATA_ERROR = -23
    NO_MORE_DATA_AVAILABLE = -22
    READING_DATA_ERROR = -21
    STREAM_IS_CURRENTLY_USED = -20
    INVALID_NAMESPACE_ID = -19
    CANNOT_DELIVER = -18
    INVALID_CRC = -17
    DUPLICATE_NAME_IN_CURRENT_HIERARCHY = -16
    CLASS_NOT_SUPPORTED_FROM_CLASS_FACTORY = -15
    CLASS_NOT_FOUND = -14
    CARDINALITY_OVERFLOW = -13
    OBJECT_NOT_FOUND = -12
    INVALID_FILE_HANDLE = -11
    INVALID_DESTINATION_REFERENCE_TYPE2 = -10
    INVALID_SOURCE_REFERENCE_TYPE2 = -9
    REFERENCES_ARE_NOT_CONNECTED = -8
    INVALID_DESTINATION_REFERENCE_TYPE = -7
    INVALID_SOURCE_REFERENCE_TYPE = -6
    ERROR_IN_SPRINTF = -5
    NOT_ENOUGH_MEMORY = -4
    INVALID_ARGUMENT_VALUE = -3
    INVALID_VALUE_TYPE = -2
    UNKNOWN_ERROR = -1
    OK = 0
    MESSAGE_TYPE_CREATED = 1
    MESSAGE_LINK_END = 2
    MESSAGE_VALUE_UNCHANGED = 3
    MESSAGE_SET_STRUCT_ATTRIBUTE = 4
    MESSAGE_RESPONSE_NEEDED = 5
    MESSAGE_ASYNC_CALL_PENDING = 6
    MESSAGE_ASSOCIATION_WRONG_SIDE = 7
    MESSAGE_LOCK_PENDING = 8
    MESSAGE_ALREADY_LOCKED = 9
    WARNING_DEFAULT_VALUE = 10
    MESSAGE_CAN_MOVE_VALUE = 11
    MESSAGE_LOAD_SUCCEEDED = 12
    MESSAGE_CONTENT_ALREADY_MOVED = 13
    WARNING_STORE_EMPTY = 14
    MESSAGE_VALUE_SWAPPED = 15
    MESSAGE_STORE_ACTIVE = 16
    # 17, 25, 26 and 33: the session already carries a lower protection level
    # than the requested one, or was legitimated to a specific level. All of
    # these mean the legitimation itself succeeded.
    SESSION_PRE_LEGITIMIZED = 17
    SERVICE_IGNORED = 18
    SERVICE_EXECUTED_WITH_PARTIAL_ERROR = 19
    SERVICE_SUBSCRIPTION_SKIP = 20
    SERVICE_SUBSCRIPTION_TOO_MANY_NOTIFIES = 21
    # The PLC answered the legitimation challenge with the wrong password.
    SERVICE_SESSION_DELEGITIMATED = 22
    END_OF_FILE = 23
    SERVICE_SUBSCRIPTION_DISABLED = 24
    SERVICE_LEGITIMATED_FOR_LEVEL2 = 25
    SERVICE_LEGITIMATED_FOR_LEVEL3 = 26
    SERVICE_MULTI_RESPONSE_PENDING = 27
    NEXT_MESSAGEBLOCK = 28
    OBJECT_SKIPPED = 29
    WARNING_DS_CANNOT_DISTRIBUTE = 30
    WARNING_DS_CONTAINER_ITEM_NOT_FOUND = 31
    WARNING_DS_PRECONDITION_MISSING = 32
    SERVICE_LEGITIMATED_FOR_LEVEL1 = 33
    SERVICE_TRANSACTION_ABORTED = 34
    BLOB_REALLOCATED = 35
    MESSAGE_DIR_ALREADY_EXISTS = 36
    TEMPORARILY_OUT_OF_RESOURCES = 37
    LEGITIM_LEVEL_CURRENTLY_DISABLED = 38
    RESCHEDULE_HANDLER = 39
    BLOB_END_REACHED = 40
    WARNING_SINGLE_ES = 41
    WARNING_MULTI_ES = 42
    WARNING_MULTI_ES_WITH_SW_TOKEN = 43
    WARNING_SKIP_DISTRIBUTION = 44
    WARNING_LOGOUT = 45
    WARNING_REDIRECTED_CALL = 46
    WARNING_PWD_FALSE_CONFIGURED = 47
    WARNING_PWD_FALSE_NOT_CONFIGURED = 48
    SERVICE_LEGITIMATED_FOR_LEVEL4 = 49
    SERVICE_PWD_EXPIRATION_WARNING = 50
    SERVICE_PWD_EXPIRATION_WARNING_LEVEL1 = 51
    SERVICE_PWD_EXPIRATION_WARNING_LEVEL2 = 52
    SERVICE_PWD_EXPIRATION_WARNING_LEVEL3 = 53
    SERVICE_PWD_EXPIRATION_WARNING_LEVEL4 = 54
    MESSAGE_NO_STORE_INTEGRITY_CHECK = 55
    CONTINUE_SYNCHRONOUSLY = 56


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
# 4 while stopped, 8 while running. On real hardware only RUN (8) is confirmed,
# read on a CPU 1215C (FW V4.2); STOP (4) is not, and the STARTUP/HOLD-family
# values in between are not pinned.
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
    """Subsystems that a return value can name as the error source.

    The source is bits 39..32 of a `ReturnValue`. 0 is the object management
    system (OMS) itself; any other source carries its own 32-bit code in bits
    31..0 instead of an OMS `ServiceResult` code, and no name for those codes
    is known.

    Members are ordered by value. The members after "Deprecated names" are
    older names for the same values, kept for compatibility; use the names
    above them. `.name` and iteration return the new names, e.g.
    ``ErrorSource(32).name == "ACE_FILESYSTEM"``.
    """

    OMS_INTERNAL = 0
    OMS = 0
    OST = 1
    IMC = 2
    LMC = 3
    WMC = 4
    EVC = 5
    OBEXEC = 6
    TIS = 7
    ALRM = 8
    SDC = 9
    PIC = 10
    STIME = 11
    RTIME = 12
    COMP = 13
    KERNEL = 14
    BUS = 15
    CIO = 16
    PNIOC_IF = 17
    XPNIOC_IF = 18
    DPM_IF = 19
    XDPM_IF = 20
    WEB = 21
    SNMP = 22
    SPS7 = 23
    SECU = 24
    CPU_PARAM = 25
    CPU_HARDWARE = 26
    RW_ATTRIB = 27
    PS = 28
    SYSTEM = 29
    SYSLOG = 30
    ACE_FILESYSTEM = 32
    ACE_COM = 33
    BACKUP = 34
    OPC_UA = 35
    OPENSSL = 36
    PRODIAG = 37
    ENERGYSUITE = 38
    CERTIFICATE_STORE = 39
    UMC_RA = 40
    CIR = 41
    HSYNC = 48
    HSYNC_RCPU = 49
    HSYNC_HCPU = 50
    ELS = 64
    ELS_L01 = 65
    ELS_L02 = 66
    ELS_L03 = 67
    ELS_L04 = 68
    ELS_L05 = 69
    ELS_L06 = 70
    ELS_L07 = 71
    ELS_L08 = 72
    ELS_L09 = 73
    ELS_L10 = 74
    ELS_L11 = 75
    ELS_L12 = 76
    ELS_L13 = 77
    ELS_L14 = 78
    ELS_L15 = 79
    ELS_L16 = 80
    ELS_L17 = 81
    ELS_L18 = 82
    ELS_L19 = 83
    ELS_L20 = 84
    ELS_L21 = 85
    ELS_L22 = 86
    ELS_L23 = 87
    ELS_L24 = 88
    ELS_L25 = 89
    ELS_L26 = 90
    T_BLOCKS = 91
    IE_CONFIG = 92
    BMC = 93
    DR = 94
    CONNECTION = 95
    SMC = 96
    SAP = 97
    CP_GPRS = 98
    CP_DPM = 99
    CP_DPS = 100
    CP_PN = 101
    CP_PNIOC = 102
    CP_MCRC_BASE = 103
    CP_MCRC_KINEMATICS_PLUS = 104
    CP_SINUMERIC = 112
    CP_SINAMICS = 113
    CP_HWDIAG = 114
    ID = 120
    CP_SM_SOFTBUS = 208
    CP_SM_COM_IF = 209
    CP_SM_CS_CC = 210
    CP_VIA_PANEL = 240
    CP_VIA_WEBSERVER = 241
    CP_VIA_ES = 242
    FWUP_WEB = 253
    FWUP_ES = 254
    DEFAULT = 255

    # --- Deprecated names ---
    OBJECT_MANAGEMENT_SYSTEM = 0
    OPERATING_STATE_CONTROL = 1
    LOAD_MEMORY_CONTROL = 3
    WORKING_MEMORY_CONTROL = 4
    TEST_DEBUG_SYSTEM = 7
    ALARMING_SYSTEM = 8
    ONBOARD_COMPILER = 13
    GENERAL_AS_OBJECT_MODEL_ERRORS = 25
    GENERAL_HARDWARE_CONFIGURATION_ERRORS = 26
    FILESYSTEM = 32
    COMMUNICATION_SYSTEM = 33
    EXECUTION_LEVEL_SYSTEM = 64


class GenericError(IntEnum):
    """Generic error categories, bits 46..40 of a `ReturnValue`.

    The category groups codes across services: an answering PLC that has none
    picks one from the request type, e.g. `GENERAL_GET_VARIABLE`.
    """

    OK = 0
    GENERAL = 1
    APPLICATION_ERROR = 2
    ACCESS_DENIED = 3
    CANT_ACTIVATE = 4
    CARDINALITY_OVERFLOW = 5
    CARDINALITY_UNDERFLOW = 6
    CLASS_NOT_ALLOWED = 7
    INVALID_ATTRIBUTE_IDENTIFIER = 8
    INVALID_DATATYPE = 9
    INVALID_OBJECT_IDENTIFIER = 10
    INVALID_PLACEMENT = 11
    INVALID_QUALIFIER = 12
    INVALID_RANGE = 13
    INVALID_SESSION = 14
    NOT_LINKED = 15
    SERVICE_TIMEOUT = 16
    DISCONNECTED = 17
    FAILED_TO_DISCONNECT = 18
    INVALID_ADDRESS = 19
    SERVICE_NOT_ALLOWED = 20
    SERVICE_NOT_CONNECTED = 21
    NOT_OWNER = 22
    TOO_MANY_REQUESTS = 23
    TOO_MANY_SESSIONS = 24
    SESSION_DELEGITIMATED = 25
    UNKNOWN_SERVICE = 26
    INVALID_STORAGE_FORMAT = 27
    INVALID_COM_FORMAT = 28
    NOT_CHANGABLE_IN_RUN = 29
    WRONG_NR_OF_ARGUMENTS_OF_INVOKE = 30
    WRONG_ARGUMENT_FORMAT_OF_INVOKE = 31
    INVOKE_FAILED = 32
    OBJECT_CANNOT_BE_STORED_TWO_TIMES_IN_PARALLEL = 33
    OBJECT_IS_LOCKED = 34
    STORE_INACTIVE = 35
    HIERARCHY_OVERFLOW = 36
    OBJECT_OR_ATTRIBUTE_ALREADY_EXIST = 37
    NOT_ENOUGH_MEMORY_AVAILABLE = 38
    NO_MEMORY_ON_STORAGE = 39
    NO_STORAGE_DETECTED = 40
    INVALID_TIMESTAMP_IN_TYPESAFE_BLOB = 41
    INVALID_FILE_NAME = 42
    INVALID_ARGUMENT_VALUE = 43
    STORE_DIRECTORY_ALREADY_USED = 44
    GENERAL_STORE_ERROR = 45
    INVALID_OBJECT_REFERENCE = 46
    REFERENCED_OBJECT_DELETED = 46
    GENERAL_CREATE = 47
    GENERAL_ADD_OBJECT = 48
    GENERAL_DELETE_OBJECT = 49
    GENERAL_GET_VARIABLE = 50
    GENERAL_SET_VARIABLE = 51
    GENERAL_GET_VARIABLE_SUBRANGE = 52
    GENERAL_SET_VARIABLE_SUBRANGE = 53
    GENERAL_GET_MULTI_VARIABLES = 54
    GENERAL_SET_MULTI_VARIABLES = 55
    GENERAL_ADD_LINK = 56
    GENERAL_REMOVE_LINK = 57
    INVALID_ID = 58
    GENERAL_COM_ERROR = 59
    NOT_CHANGABLE_IN_ERROR_STATE = 60
    MULTI_ES_NOT_SUPPORTED = 61
    SERVICE_ABORTED = 62
    SOURCE_FILE_NOT_EXISTING = 63
    INVALID_VERSION = 64
    COMM_FORMAT_DIFFERS_FROM_STORE_FORMAT = 65
    GENERAL_TRANSACTION = 66
    DISTRIBUTION = 67
    GENERAL_PATH_NOT_FOUND = 68
    GENERAL_END_OF_FILE = 69
    GENERAL_FS_WRITE_PROTECTED = 70
    GENERAL_FS_DISK_FULL = 71
    GENERAL_FS_INVALID_PATH_NAME = 72
    WSTRING_NOT_SUPPORTED = 73
    TRANSACTION_ABORTED = 74
    STORE_FORCE_STORE = 75
    GENERAL_INTEGRITY = 76
    MULTI_ES_CONFLICT = 77
    TEMPORARILY_OUT_OF_RESOURCES = 78
    MULTI_ES_LIMIT_EXCEEDED = 79
    MULTI_ES_INCOMPATIBLE_OTHER_ES_VERSION = 80
    CONCURRENT_TRANSACTION_RUNNING = 81
    SSL_ERROR = 82
    RH_PLC_PROXY_TREE_UNKNOWN = 83
    RH_PLC_PROXY_TREE_NON_REDUNDANT = 84
    SERVICE_NOT_AVAILABLE = 85
    TLS_ERROR = 86
    SECURITY = 87
    MAX_NUMBER = 127


def _enum_label(enum: type[IntEnum], value: int) -> str:
    try:
        return f"{enum(value).name} ({value})"
    except ValueError:
        return str(value)


@dataclass(frozen=True)
class ReturnValue:
    """A decoded 64-bit S7CommPlus return value.

    Layout::

        63      failed: the only failure test; positive codes are successes with information
        62      a ResponseExtension object comes with the reply
        61..48  firmware-internal, not decoded
        47      set by the side that answered the request
        46..40  generic category (`GenericError`)
        39..32  source subsystem (`ErrorSource`), 0 = OMS
        31..16  firmware-internal, not decoded  (source 0 only)
        15..0   signed 16-bit `ServiceResult`   (source 0 only)
        31..0   signed 32-bit subsystem code    (any other source)

    The firmware-internal bits differ between firmware versions for the same
    code, so match on `code`, not on `raw`.

    Example::

        >>> rv = ReturnValue.from_int(0x8020AB001992FFF4)
        >>> rv.failed, rv.code, rv.generic
        (True, -12, 43)
        >>> str(rv)
        'OBJECT_NOT_FOUND (-12), generic INVALID_ARGUMENT_VALUE (43)'
    """

    raw: int
    failed: bool
    has_extension: bool
    from_responder: bool
    generic: int
    source: int
    code: int

    @classmethod
    def from_int(cls, value: int) -> "ReturnValue":
        """Decode a return value given as an unsigned 64-bit or a signed Python int.

        A small negative number (above -65536) is taken as a bare legacy code
        and decoded as a failed OMS composite carrying that code, with every
        other field zero.

        Args:
            value: The return value as decoded from the wire.

        Returns:
            The decoded fields.

        Raises:
            ValueError: If the value fits neither a signed nor an unsigned 64-bit integer.
        """
        if not -(1 << 63) <= value < 1 << 64:
            raise ValueError(f"ReturnValue {value} does not fit in 64 bits")
        if -(1 << 16) < value < 0:
            value = (1 << 63) | (value & 0xFFFF)
        raw = value % (1 << 64)
        source = (raw >> 32) & 0xFF
        if source:
            low = raw & 0xFFFFFFFF
            code = low - (1 << 32) if low & 0x80000000 else low
        else:
            low = raw & 0xFFFF
            code = low - 0x10000 if low & 0x8000 else low
        return cls(
            raw=raw,
            failed=bool(raw >> 63),
            has_extension=bool((raw >> 62) & 1),
            from_responder=bool((raw >> 47) & 1),
            generic=(raw >> 40) & 0x7F,
            source=source,
            code=code,
        )

    def __str__(self) -> str:
        parts = [f"subsystem code 0x{self.code & 0xFFFFFFFF:08X}" if self.source else _enum_label(ServiceResult, self.code)]
        if self.generic:
            parts.append(f"generic {_enum_label(GenericError, self.generic)}")
        if self.source:
            parts.append(f"source {_enum_label(ErrorSource, self.source)}")
        return ", ".join(parts)


def service_result_code(return_value: int) -> int:
    """Extract the sign-extended low 16 bits of a composite return value.

    A plain small negative number is already the code (legacy encoding) and is
    returned unchanged.

    .. deprecated:: 0.4.0
        Use ``ReturnValue.from_int(return_value).code`` instead. It differs
        when the source (bits 39..32) is non-zero: it then returns the
        subsystem's 32-bit code, where this function keeps the low 16 bits.
    """
    warnings.warn(
        "service_result_code() is deprecated; use ReturnValue.from_int(return_value).code instead",
        DeprecationWarning,
        stacklevel=2,
    )
    if -(1 << 16) < return_value < 0:
        return return_value
    low = return_value & 0xFFFF
    return low - 0x10000 if low & 0x8000 else low
