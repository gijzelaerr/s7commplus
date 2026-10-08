"""Validate the shape of the order-number -> device-name table.

The table in ``s7commplus/devices.py`` is hand-copied, so this script checks
what can be checked without an external source: every key is a plausible
SIMATIC order number (6ES7/6AG1 MLFB form), every value is non-empty, every
entry classifies into one of the supported families, and the table stays
within the S7-1200/1500 class (no classic S7-300/400 modules, which speak
classic S7, not S7CommPlus).

Run from the repository root:

    python tools/check_devices_table.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from s7commplus.devices import DEVICE_NAMES, device_family  # noqa: E402

_MLFB_SHAPE = re.compile(r"^6(?:ES7|AG1) [0-9]{3}-[0-9A-Z]{4,6}-[0-9A-Z]{4,5}$")

problems: list[str] = []
for order_number, name in sorted(DEVICE_NAMES.items()):
    if not _MLFB_SHAPE.match(order_number) and "SIM" not in order_number and "841" not in order_number:
        problems.append(f"key {order_number!r} is not a 6ES7/6AG1 MLFB")
    if not name or not name.strip():
        problems.append(f"{order_number!r} has an empty name")
    if name != name.strip():
        problems.append(f"{order_number!r} name has surrounding whitespace")
    family = device_family(order_number)
    if family is None:
        problems.append(f"{order_number!r} ({name!r}) does not classify")

families = {device_family(k) for k in DEVICE_NAMES}
allowed = {"s7-1200", "s7-1500", "s7-1500-sp", "plcsim", "et200"}
if not families <= allowed:
    problems.append(f"unexpected families present: {sorted(families - allowed)}")

# The PLCSIM and simulation entries are non-MLFB keys by design; everything
# else must match the shape above.
non_mlfb = [k for k in DEVICE_NAMES if not _MLFB_SHAPE.match(k) and "SIM" not in k and "841" not in k]
if non_mlfb:
    problems.append(f"keys neither MLFB nor simulation entries: {non_mlfb}")

if problems:
    print(f"devices table: {len(problems)} problem(s)")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print(f"devices table: {len(DEVICE_NAMES)} entries OK ({', '.join(sorted(str(f) for f in families))})")
