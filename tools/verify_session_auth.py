"""One offline workflow for SessionKey artifact and evidence verification.

Default: complete runtime/glue/key and upstream known-answer inventories.
--upstream-root: also independently compare source-derived programs/data and
all vendored keys/fixtures with the pinned checkout. --models regenerates the
saved Boolean models and checks setup proof accounting (not a certificate).
No source is downloaded, files rewritten, or PLC contacted by this command.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from tools.verify_session_auth_artifacts import REPOSITORY_ROOT, verify as artifacts
from tools.verify_session_auth_evidence import verify as evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", type=Path)
    parser.add_argument("--models", action="store_true")
    args = parser.parse_args(argv)
    errors = artifacts() + evidence(upstream_root=args.upstream_root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    commands: list[list[str]] = []
    if args.upstream_root is not None:
        commands.extend(
            [
                [str(REPOSITORY_ROOT / "tools" / script), "--upstream-root", str(args.upstream_root)]
                for script in ("verify_session_auth_upstream.py", "verify_transpiled_monoliths.py")
            ]
        )
    if args.models:
        commands.extend(
            [
                ["-m", f"tools.{module}", "--verify", str(REPOSITORY_ROOT / "tools" / model)]
                for module, model in (
                    ("recover_monolith5", "monolith5_model.json"),
                    ("recover_monolith5_gates", "monolith5_gate_model.json"),
                    ("recover_monolith7_tail", "monolith7_tail_model.json"),
                    ("recover_monolith7_middle", "monolith7_middle_model.json"),
                    ("recover_monolith7_full", "monolith7_full_model.json"),
                )
            ]
        )
        commands.append(["-m", "tools.prove_transform7_setup_integer"])
        commands.append(["-m", "tools.prove_transform7_reference_topology"])
    for command in commands:
        result = subprocess.run([sys.executable, *command], cwd=REPOSITORY_ROOT, check=False)
        if result.returncode:
            return result.returncode
    print("Verified SessionKey runtime/glue/key and known-answer inventories; requested source/model checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
