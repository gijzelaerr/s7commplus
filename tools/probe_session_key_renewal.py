#!/usr/bin/env python3
"""Try each legacy SessionKey renewal layout against a PLC and report which ones it accepts.

For every layout the probe opens its own connection, renews the SessionKey at
once and then sends three read requests under the new key (the challenge read
a renewal starts with). A layout counts as accepted only when the PLC answers
those. The probe writes nothing but the session's own key. A refused renewal
costs that one connection.

``reference`` is the request the client sends today. On a CPU that fails its
renewals it should be refused here too; if it is accepted, renewing right
after the connect does not reproduce the failure and the table says little.

The report holds no PLC address. Background: issue #184.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from s7commplus.client import S7CommPlusClient  # noqa: E402
from s7commplus.connection import _SESSION_KEY_RENEWAL_LAYOUTS, _build_get_var_substreamed_payload  # noqa: E402
from s7commplus.protocol import FunctionCode, LegitimationId  # noqa: E402

# Kept in step with tools/run_real_plc_acceptance.py.
PASSWORD_ENV = "S7COMMPLUS_TEST_PASSWORD"
READS_AFTER_RENEWAL = 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plc-ip", required=True, help="PLC address (used for the connection only; never printed)")
    parser.add_argument("--plc-port", type=int, default=102)
    parser.add_argument(
        "--tls",
        choices=("off", "auto"),
        default="off",
        help="'auto' tries TLS first and falls back to the legacy session, as the client's auto mode does (default: off)",
    )
    parser.add_argument(
        "--layouts",
        nargs="+",
        choices=_SESSION_KEY_RENEWAL_LAYOUTS,
        default=list(_SESSION_KEY_RENEWAL_LAYOUTS),
        help="layouts to try, in order (default: all)",
    )
    parser.add_argument("--pause", type=float, default=2.0, help="seconds to wait between connections (default: 2)")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="log every frame; the log contains the PLC address and key material, so review it before sharing",
    )
    return parser.parse_args()


def scrub(text: str, host: str) -> str:
    """Remove the PLC address from a message before it is printed."""
    return text.replace(host, "<plc>")


def probe_layout(layout: str, args: argparse.Namespace) -> tuple[str, str, str]:
    """Renew once with ``layout`` on a fresh connection. Returns (session, verdict, detail)."""
    client = S7CommPlusClient()
    session = "?"
    try:
        client.connect(
            args.plc_ip,
            args.plc_port,
            use_tls="auto" if args.tls == "auto" else False,
            password=os.environ.get(PASSWORD_ENV) or None,
            legacy_session_key_refresh_interval=None,
        )
        connection = client._connection
        assert connection is not None
        if connection._session_key is None:
            return "no SessionKey", "skipped", "the session has no legacy SessionKey, so there is nothing to renew"
        session = f"family {int(connection._v1_session_key_family):02x}, OMS {client.session_oms_version}"

        connection._session_key_renewal_layout = layout
        try:
            with connection._request_lock:
                connection._renew_session_key_locked()
        except Exception as exc:
            return session, "refused", scrub(f"{type(exc).__name__}: {exc}", args.plc_ip)

        try:
            for _ in range(READS_AFTER_RENEWAL):
                read = _build_get_var_substreamed_payload(connection._session_id, LegitimationId.SERVER_SESSION_REQUEST)
                connection.send_request(FunctionCode.GET_VAR_SUBSTREAMED, read, integrity_tail=4)
        except Exception as exc:
            return session, "renewed, then failed", scrub(f"{type(exc).__name__}: {exc}", args.plc_ip)
        return session, "accepted", f"{READS_AFTER_RENEWAL} requests answered under the new key"
    except Exception as exc:
        return session, "error", scrub(f"{type(exc).__name__}: {exc}", args.plc_ip)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.CRITICAL, format="[%(asctime)s] [%(levelname)s] %(message)s"
    )

    results: list[tuple[str, str, str, str]] = []
    for index, layout in enumerate(args.layouts):
        if index:
            time.sleep(args.pause)
        session, verdict, detail = probe_layout(layout, args)
        results.append((layout, session, verdict, detail))

    print("| Layout | Session | Result | Detail |")
    print("| --- | --- | --- | --- |")
    for layout, session, verdict, detail in results:
        print(f"| `{layout}` | {session} | {verdict} | {detail} |")
    return 0 if any(verdict == "accepted" for _, _, verdict, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
