"""connect() keeps the positional parameters 0.2.0 released; every option added since is keyword-only."""

import inspect

from s7commplus import AsyncClient, Client

POSITIONAL = inspect.Parameter.POSITIONAL_OR_KEYWORD


def _positional(method: object) -> list[str]:
    return [p.name for p in inspect.signature(method).parameters.values() if p.kind is POSITIONAL]  # type: ignore[arg-type]


def test_sync_connect_positional_parameters_are_those_of_0_2_0() -> None:
    assert _positional(Client.connect) == [
        "self",
        "host",
        "port",
        "rack",
        "slot",
        "use_tls",
        "tls_cert",
        "tls_key",
        "tls_ca",
        "password",
        "allow_legacy_key_fallback",
        "legacy_session_key_refresh_interval",
    ]


def test_async_connect_takes_every_option_by_keyword() -> None:
    assert _positional(AsyncClient.connect) == ["self", "host", "port", "rack", "slot"]
