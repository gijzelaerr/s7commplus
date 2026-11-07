"""The sync and async clients expose the same public API, apart from the gaps listed here.

A public method added to one client fails these tests until it is added to the
other, or listed below with the reason it differs. A listed gap that was closed
fails them too, so the lists cannot go stale.
"""

import inspect
from typing import Any

import pytest

from s7commplus import AsyncClient, Client

# Sync notifications go to callbacks; async ones to ``subscription_queue``.
SYNC_ONLY = {"add_subscription_callback", "remove_subscription_callback"}

ASYNC_ONLY = {
    "subscription_queue",  # see SYNC_ONLY
    # The async client is one class; on the sync side these are on ``Client._connection``.
    "alarm_texts_and_domain_filter",
    "legacy_s7_1500",
    "object_qualifier_version",
    "oms_secret",
    "subscription_container_id",
    "write_delete_qualifier_version",
}

# Same parameters, but after ``slot`` they are keyword-only in the async client and
# can also be positional in the sync one, in a different order.
PARAMETER_KINDS_DIFFER = {"connect"}


def _public_members(cls: type) -> set[str]:
    return {name for name, _ in inspect.getmembers(cls) if not name.startswith("_")}


SHARED = sorted(_public_members(Client) & _public_members(AsyncClient))
SHARED_METHODS = [name for name in SHARED if inspect.isfunction(inspect.getattr_static(Client, name))]


def _parameters(cls: type, name: str) -> dict[str, tuple[Any, Any]]:
    signature = inspect.signature(getattr(cls, name))
    return {parameter.name: (parameter.kind, parameter.default) for parameter in signature.parameters.values()}


def test_members_only_on_the_sync_client() -> None:
    assert _public_members(Client) - _public_members(AsyncClient) == SYNC_ONLY


def test_members_only_on_the_async_client() -> None:
    assert _public_members(AsyncClient) - _public_members(Client) == ASYNC_ONLY


@pytest.mark.parametrize("name", SHARED)
def test_shared_member_is_the_same_kind(name: str) -> None:
    sync_kind = type(inspect.getattr_static(Client, name))
    async_kind = type(inspect.getattr_static(AsyncClient, name))
    assert sync_kind is async_kind


@pytest.mark.parametrize("name", SHARED_METHODS)
def test_shared_method_has_the_same_parameters(name: str) -> None:
    sync_parameters = _parameters(Client, name)
    async_parameters = _parameters(AsyncClient, name)
    if name in PARAMETER_KINDS_DIFFER:
        assert {key: value[1] for key, value in sync_parameters.items()} == {
            key: value[1] for key, value in async_parameters.items()
        }
    else:
        assert list(sync_parameters.items()) == list(async_parameters.items())


def test_listed_parameter_differences_still_differ() -> None:
    for name in PARAMETER_KINDS_DIFFER:
        assert list(_parameters(Client, name).items()) != list(_parameters(AsyncClient, name).items())
