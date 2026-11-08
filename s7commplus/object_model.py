"""Attribute id tables for the object classes this package works with.

S7CommPlus is a tagged object model: a PLC's program and configuration is a
tree of objects, each of a *class*, and each class carries numbered
attributes. Knowing an attribute's id and name turns an opaque number in an
EXPLORE response into something a caller can act on, and is what the
``browse()``/tag-catalog layer builds on.

This module covers the classes the clients already read or write — the
session, program blocks, the CPU execution unit, subscriptions and the
alarm subsystem. It is deliberately a curated slice, not a dump of every
class a PLC defines. DataBlock is absent on purpose: a data block's
attributes are its per-tag tree (the ``browse()`` layer), not a fixed set
of attribute ids.

Source: attribute ids 233, 306, 319, 2521 and the subscription ids are
thomas-v2/S7CommPlusDriver/Core/Ids.cs and this package's own
hardware-validated paths. The rest come from TIA Portal session captures
(CreateObject and EXPLORE responses); none are verified against a live PLC
beyond what this package's existing tests already cover.
"""

from __future__ import annotations

from typing import Optional

#: Object class id -> class name.
CLASS_NAMES: dict[int, str] = {
    287: "ServerSession",
    2520: "PLCProgram",
    0x9EA: "Block",
    0x883: "CPUexecUnit",
    1001: "Subscription",
    0x88E: "AlarmSubsystem",
}

#: (class id, attribute id) -> attribute name.
ATTRIBUTE_NAMES: dict[tuple[int, int], str] = {
    # --- ServerSession (attribute tree of the CreateObject response) ---
    (287, 289): "ClientID",
    (287, 296): "User",
    (287, 297): "Application",
    (287, 298): "Host",
    (287, 299): "Role",
    (287, 300): "ClientRID",
    (287, 301): "ClientComment",
    (287, 302): "Timeout",
    (287, 303): "Challenge",
    (287, 304): "Response",
    (287, 305): "Roles",
    (287, 306): "Version",
    # --- Block (base class of program blocks) ---
    (0x9EA, 0x9D9): "BlockNumber",
    (0x9EA, 0x9DA): "AutoNumbering",
    (0x9EA, 0x9DB): "BlockLanguage",
    (0x9EA, 0x9DC): "KnowhowProtected",
    (0x9EA, 0x9DF): "Unlinked",
    (0x9EA, 0x9E4): "CRC",
    (0x9EA, 0x9E5): "BodyDescription",
    (0x9EA, 0x11E2): "TypeInfo",
    (0x9EA, 233): "TypeName",
    # --- CPUexecUnit ---
    (0x883, 0x877): "OperatingStateREQ",
    (0x883, 0xD9E): "OperatingState",
    (0x883, 0x1F80): "AlarmOBsLoad_LastPC",
    (0x883, 0x1F81): "ProgramCycleLoadActual",
    (0x883, 52): "TypeName",  # ObjectVariableTypeName, shared id
    # --- Subscription ---
    (1001, 1005): "ReferenceTriggerMode",
    (1001, 1040): "RouteMode",
    (1001, 1041): "Active",
    (1001, 1048): "ReferenceList",
    (1001, 1049): "CycleTime",
    (1001, 1050): "DelayTime",
    (1001, 1051): "Disabled",
    (1001, 1052): "Count",
    (1001, 1053): "CreditLimit",
    (1001, 1054): "Ticks",
    # --- AlarmSubsystem ---
    (0x88E, 2659): "AlarmDomain",
    (0x88E, 2660): "ItsAlarmSubsystem",
    (0x88E, 2662): "ClassRID",
    (0x88E, 2667): "UpdateRelevantDAI",
}


def attribute_name(class_id: int, attribute_id: int) -> Optional[str]:
    """Return the attribute name for a (class id, attribute id) pair.

    ``None`` when the pair is not in the table; callers should fall back to
    a numeric rendering rather than treat that as an error, since PLCs define
    far more attributes than this curated slice records.
    """
    return ATTRIBUTE_NAMES.get((class_id, attribute_id))


def describe_attribute(class_id: int, attribute_id: int) -> str:
    """Render a (class id, attribute id) pair as a readable string.

    >>> describe_attribute(0x9EA, 0x9DB)
    'Block.BlockLanguage'
    >>> describe_attribute(2574, 99999)
    'class 2574 attribute 99999'
    """
    class_name = CLASS_NAMES.get(class_id, f"class {class_id}")
    name = attribute_name(class_id, attribute_id)
    return f"{class_name}.{name}" if name is not None else f"{class_name} attribute {attribute_id}"
