"""The sync and async clients expose the same public API, apart from the gaps listed here.

A public method added to one client fails these tests until it is added to the
other, or listed below with the reason it differs. A listed gap that was closed
fails them too, so the lists cannot go stale.
"""

import ast
import inspect
import textwrap
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


# --- Methods that differ only by ``await`` ---------------------------------------------
#
# These bodies are the same in both clients apart from ``await``/``async``; they cannot be
# shared, because each calls its own client's I/O. Comparing
# them as syntax trees, with docstrings and awaits removed, keeps a change to one from
# silently missing the other. A method that has to differ comes off this list, with the
# reason in its docstring.
SAME_BUT_AWAIT = [
    "_auto_refresh_check",
    "_explore_type_info_container",
    "_open_connection_with_key_fallback",
    "_plan_values",
    "_probe_family_keys",
    "_read_resolved_tags",
    "_read_type_info_time",
    "_read_typeinfo_rid",
    "_reconnect",
    "_recover_dropped_connection",
    "_resolve_tags",
    "_with_reconnect",
    "authenticate",
    "browse",
    "create_alarm_subscription",
    "create_subscription",
    "create_subscriptions",
    "db_read",
    "db_read_multi",
    "db_write",
    "db_write_multi",
    "delete_alarm_subscription",
    "delete_subscription",
    "download_block",
    "explore",
    "explore_xml",
    "get_cpu_state",
    "iter_subscription_notifications",
    "list_datablocks",
    "program_objects",
    "read_alarms",
    "read_area",
    "read_symbolic",
    "read_symbolic_multi",
    "read_tag",
    "read_tags",
    "read_value",
    "read_values",
    "reconnect",
    "refresh_caches_if_program_changed",
    "refresh_tag_catalog",
    "request_operating_state",
    "resolve_tag",
    "resubscribe",
    "set_plc_operating_state",
    "upload_block",
    "write_area",
    "write_multi",
    "write_symbolic",
    "write_tag",
    "write_tags",
    "write_value",
    "write_values",
]


class _WithoutAwait(ast.NodeTransformer):
    """Turn an async function into the sync one it mirrors, without its docstring."""

    def visit_Await(self, node: ast.Await) -> ast.AST:
        return self.visit(node.value)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> ast.AST:
        self.generic_visit(node)
        return ast.copy_location(ast.With(items=node.items, body=node.body), node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AST:
        self.generic_visit(node)
        return ast.copy_location(ast.For(target=node.target, iter=node.iter, body=node.body, orelse=node.orelse), node)


def _body_without_await(cls: type, name: str) -> str:
    source = textwrap.dedent(inspect.getsource(inspect.unwrap(getattr(cls, name))))
    function = ast.parse(source).body[0]
    assert isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    module = ast.Module(body=[_WithoutAwait().visit(statement) for statement in body], type_ignores=[])
    return ast.unparse(ast.fix_missing_locations(module))


@pytest.mark.parametrize("name", SAME_BUT_AWAIT)
def test_method_differs_from_its_twin_only_by_await(name: str) -> None:
    assert _body_without_await(Client, name) == _body_without_await(AsyncClient, name)
