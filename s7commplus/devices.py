"""Map Siemens order numbers (MLFB) to device names for S7-1200/1500 controllers.

The PAOM string a PLC reports in its ServerSessionVersion carries the
order number (for example ``6ES7 215-1AG40-0XB0``); this module turns it
into the human-readable module name (``CPU 1215C DC/DC/DC``) and a device
family classification.

Source: Siemens SIMATIC order-number scheme, transcribed from TIA Portal's
device catalog. Hand-copied and not independently checkable; the
check_devices_table script validates its shape. Not verified against a live
PLC.
"""

from __future__ import annotations

import re


# Order number -> module name. Covers S7-1200 and S7-1500 controllers,
# their SIPLUS wide-temperature variants (6AG1 ...), the S7-1500 software
# controllers, and PLCSIM. Classic S7-300/400 modules are deliberately
# absent: they speak classic S7, not S7CommPlus.
DEVICE_NAMES: dict[str, str] = {
    "6AG1 212-1AE40-2XB0": "CPU 1212C DC/DC/DC SIPLUS",
    "6AG1 212-1AE40-4XB0": "CPU 1212C DC/DC/DC SIPLUS",
    "6AG1 212-1BE40-2XB0": "CPU 1212C AC/DC/Rly SIPLUS",
    "6AG1 212-1BE40-4XB0": "CPU 1212C AC/DC/Rly SIPLUS",
    "6AG1 212-1HE40-2XB0": "CPU 1212C DC/DC/Rly SIPLUS",
    "6AG1 212-1HE40-4XB0": "CPU 1212C DC/DC/Rly SIPLUS",
    "6AG1 214-1AG40-2XB0": "CPU 1214C DC/DC/DC SIPLUS",
    "6AG1 214-1AG40-4XB0": "CPU 1214C DC/DC/DC SIPLUS",
    "6AG1 214-1AG40-5XB0": "CPU 1214C DC/DC/DC SIPLUS",
    "6AG1 214-1BG40-2XB0": "CPU 1214C AC/DC/Rly SIPLUS",
    "6AG1 214-1BG40-4XB0": "CPU 1214C AC/DC/Rly SIPLUS",
    "6AG1 214-1BG40-5XB0": "CPU 1214C AC/DC/Rly SIPLUS",
    "6AG1 214-1HG40-2XB0": "CPU 1214C DC/DC/Rly SIPLUS",
    "6AG1 214-1HG40-4XB0": "CPU 1214C DC/DC/Rly SIPLUS",
    "6AG1 214-1HG40-5XB0": "CPU 1214C DC/DC/Rly SIPLUS",
    "6AG1 215-1AG40-2XB0": "CPU 1215C DC/DC/DC SIPLUS",
    "6AG1 215-1AG40-4XB0": "CPU 1215C DC/DC/DC SIPLUS",
    "6AG1 215-1AG40-5XB0": "CPU 1215C DC/DC/DC SIPLUS",
    "6AG1 215-1BG40-2XB0": "CPU 1215C AC/DC/Rly SIPLUS",
    "6AG1 215-1BG40-4XB0": "CPU 1215C AC/DC/Rly SIPLUS",
    "6AG1 215-1BG40-5XB0": "CPU 1215C AC/DC/Rly SIPLUS",
    "6AG1 215-1HG40-2XB0": "CPU 1215C DC/DC/Rly SIPLUS",
    "6AG1 215-1HG40-4XB0": "CPU 1215C DC/DC/Rly SIPLUS",
    "6AG1 215-1HG40-5XB0": "CPU 1215C DC/DC/Rly SIPLUS",
    "6AG1 511-1AK00-2AB0": "CPU 1511-1 PN SIPLUS",
    "6AG1 511-1AK00-7AB0": "CPU 1511-1 PN SIPLUS",
    "6AG1 513-1AL00-2AB0": "CPU 1513-1 PN SIPLUS",
    "6AG1 513-1AL00-7AB0": "CPU 1513-1 PN SIPLUS",
    "6AG1 516-3AN00-2AB0": "CPU 1516-3 PN/DP SIPLUS",
    "6AG1 516-3AN00-7AB0": "CPU 1516-3 PN/DP SIPLUS",
    "6ES7 211-1AD30-0XB0": "CPU 1211C DC/DC/DC",
    "6ES7 211-1AE31-0XB0": "CPU 1211C DC/DC/DC",
    "6ES7 211-1AE40-0XB0": "CPU 1211C DC/DC/DC",
    "6ES7 211-1BD30-0XB0": "CPU 1211C AC/DC/Rly",
    "6ES7 211-1BE31-0XB0": "CPU 1211C AC/DC/Rly",
    "6ES7 211-1BE40-0XB0": "CPU 1211C AC/DC/Rly",
    "6ES7 211-1HD30-0XB0": "CPU 1211C DC/DC/Rly",
    "6ES7 211-1HE31-0XB0": "CPU 1211C DC/DC/Rly",
    "6ES7 211-1HE40-0XB0": "CPU 1211C DC/DC/Rly",
    "6ES7 212-1AD30-0XB0": "CPU 1212C DC/DC/DC",
    "6ES7 212-1AE31-0XB0": "CPU 1212C DC/DC/DC",
    "6ES7 212-1AE40-0XB0": "CPU 1212C DC/DC/DC",
    "6ES7 212-1BD30-0XB0": "CPU 1212C AC/DC/Rly",
    "6ES7 212-1BE31-0XB0": "CPU 1212C AC/DC/Rly",
    "6ES7 212-1BE40-0XB0": "CPU 1212C AC/DC/Rly",
    "6ES7 212-1HD30-0XB0": "CPU 1212C DC/DC/Rly",
    "6ES7 212-1HE31-0XB0": "CPU 1212C DC/DC/Rly",
    "6ES7 212-1HE40-0XB0": "CPU 1212C DC/DC/Rly",
    "6ES7 214-1AE30-0XB0": "CPU 1214C DC/DC/DC",
    "6ES7 214-1AF40-0XB0": "CPU 1214FC DC/DC/DC",
    "6ES7 214-1AG31-0XB0": "CPU 1214C DC/DC/DC",
    "6ES7 214-1AG40-0XB0": "CPU 1214C DC/DC/DC",
    "6ES7 214-1BE30-0XB0": "CPU 1214C AC/DC/Rly",
    "6ES7 214-1BG31-0XB0": "CPU 1214C AC/DC/Rly",
    "6ES7 214-1BG40-0XB0": "CPU 1214C AC/DC/Rly",
    "6ES7 214-1HE30-0XB0": "CPU 1214C DC/DC/Rly",
    "6ES7 214-1HF40-0XB0": "CPU 1214FC DC/DC/RLY",
    "6ES7 214-1HG31-0XB0": "CPU 1214C DC/DC/Rly",
    "6ES7 214-1HG40-0XB0": "CPU 1214C DC/DC/Rly",
    "6ES7 215-1AF40-0XB0": "CPU 1215FC DC/DC/DC",
    "6ES7 215-1AG31-0XB0": "CPU 1215C DC/DC/DC",
    "6ES7 215-1AG40-0XB0": "CPU 1215C DC/DC/DC",
    "6ES7 215-1BG31-0XB0": "CPU 1215C AC/DC/Rly",
    "6ES7 215-1BG40-0XB0": "CPU 1215C AC/DC/Rly",
    "6ES7 215-1HF40-0XB0": "CPU 1215FC DC/DC/RLY",
    "6ES7 215-1HG31-0XB0": "CPU 1215C DC/DC/Rly",
    "6ES7 215-1HG40-0XB0": "CPU 1215C DC/DC/Rly",
    "6ES7 217-1AG40-0XB0": "CPU 1217C DC/DC/DC",
    "6ES7 510-1DJ00-0AB0": "CPU 1510SP-1 PN",
    "6ES7 510-1DJ01-0AB0": "CPU 1510SP-1 PN",
    "6ES7 510-1SJ00-0AB0": "CPU 1510SP F-1 PN",
    "6ES7 510-1SJ01-0AB0": "CPU 1510SP F-1 PN",
    "6ES7 511-1AK00-0AB0": "CPU 1511-1 PN",
    "6ES7 511-1AK01-0AB0": "CPU 1511-1 PN",
    "6ES7 511-1CK00-0AB0": "CPU 1511C-1 PN",
    "6ES7 511-1FK00-0AB0": "CPU 1511F-1 PN",
    "6ES7 511-1FK01-0AB0": "CPU 1511F-1 PN",
    "6ES7 512-1CK00-0AB0": "CPU 1512C-1 PN",
    "6ES7 512-1DK00-0AB0": "CPU 1512SP-1 PN",
    "6ES7 512-1DK01-0AB0": "CPU 1512SP-1 PN",
    "6ES7 512-1SK00-0AB0": "CPU 1512SP F-1 PN",
    "6ES7 512-1SK01-0AB0": "CPU 1512SP F-1 PN",
    "6ES7 512-1SM03-0AB0": "CPU 1512SP F-1 PN",
    "6ES7 513-1AL00-0AB0": "CPU 1513-1 PN",
    "6ES7 513-1AL01-0AB0": "CPU 1513-1 PN",
    "6ES7 513-1FL00-0AB0": "CPU 1513F-1 PN",
    "6ES7 513-1FL01-0AB0": "CPU 1513F-1 PN",
    "6ES7 515-2AM00-0AB0": "CPU 1515-2 PN",
    "6ES7 515-2AM01-0AB0": "CPU 1515-2 PN",
    "6ES7 515-2FM00-0AB0": "CPU 1515F-2 PN",
    "6ES7 515-2FM01-0AB0": "CPU 1515F-2 PN",
    "6ES7 516-3AN00-0AB0": "CPU 1516-3 PN/DP",
    "6ES7 516-3AN01-0AB0": "CPU 1516-3 PN/DP",
    "6ES7 516-3FN00-0AB0": "CPU 1516F-3 PN/DP",
    "6ES7 516-3FN01-0AB0": "CPU 1516F-3 PN/DP",
    "6ES7 517-3AP00-0AB0": "CPU 1517-3 PN/DP",
    "6ES7 517-3FP00-0AB0": "CPU 1517F-3 PN/DP",
    "6ES7 518-4AP00-0AB0": "CPU 1518-4 PN/DP",
    "6ES7 518-4FP00-0AB0": "CPU 1518F-4 PN/DP",
    "6ES7 672-5AC00-0YA0": "CPU 1505S",
    "6ES7 672-7AC00-0YA0": "CPU 1507S",
    "6ES7 677-2AA30-0AA0": "CPU 1515SP PC",
    "6ES7 841-0CC05-0YA5": "CPU 841 (PLCSIM)",
    "6ES7 SIM-01200-VPLC": "CPU-1200 Simulation",
    "6ES7 SIM-01500-VPLC": "CPU-1500 Simulation",
    "6ES7 SIM-ET200-VPLC": "CPU-ET200SP Simulation",
}


def device_name(order_number: str) -> str | None:
    """Return the module name for an order number, or ``None`` if unknown.

    Leading/trailing whitespace and the trailing firmware part of a PAOM
    string are tolerated: the middle field of
    ``1;6ES7 215-1AG40-0XB0;V4.2`` resolves like the bare order number.
    """
    key = order_number.strip()
    if ";" in key:
        fields = key.split(";")
        key = fields[1].strip() if len(fields) >= 2 else key
    return DEVICE_NAMES.get(key)


def device_family(order_number: str) -> str | None:
    """Classify an order number into a controller family.

    Returns ``"s7-1200"``, ``"s7-1500"``, ``"s7-1500-sp"`` (the software
    and SP controllers), ``"plcsim"`` or ``"et200"``; ``None`` when the order
    number is unknown or not a controller.
    """
    name = device_name(order_number)
    if name is None:
        return None
    upper = name.upper()
    if "ET200" in upper:
        return "et200"
    if "SIM" in upper or "PLCSIM" in upper or "SIMULATION" in upper:
        return "plcsim"
    # SP variants run "1512SP", "1515SP PC"; software controllers "1505S"/"1507S".
    if re.search(r"\b1\d{3}SP|\b15\d\dS\b", upper):
        return "s7-1500-sp"
    if "CPU 15" in upper:
        return "s7-1500"
    if "CPU 12" in upper:
        return "s7-1200"
    return None
