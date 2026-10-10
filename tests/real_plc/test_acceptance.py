"""Executable pytest-bdd bindings for the versioned real-PLC specification."""

from __future__ import annotations

import os
import ssl
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from s7commplus.error import S7AuthenticationError, S7Error
from tests.real_plc import support
from tests.real_plc.support import (
    CLIENT_KINDS,
    DB_SIZE,
    FIXTURE_MEMBERS,
    MEMBERS_BY_NAME,
    NAMED_WRITE_VALUES,
    NOTIFICATION_TIMEOUT,
    PASSWORD_ENV,
    PENDING_FEATURES,
    WRITE_VALUES,
    PLCAdapter,
    PLCConfig,
    ScratchRestoreGuard,
    assert_canonical_fixture,
    canonical_fixture_bytes,
    fixture_entries,
    untrusted_ca_certificate,
)

pytestmark = [pytest.mark.e2e, pytest.mark.real_plc]
scenarios("../features/real_plc")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Run every scenario once per client selected with ``--plc-client``."""
    if "plc_client_kind" in metafunc.fixturenames:
        selected = metafunc.config.getoption("--plc-client")
        kinds = CLIENT_KINDS if selected == "both" else (selected,)
        metafunc.parametrize("plc_client_kind", kinds, indirect=True)


@pytest.fixture(autouse=True)
def plc_client_kind(request: pytest.FixtureRequest) -> str:
    return str(getattr(request, "param", "sync"))


@pytest.fixture
def plc_config(request: pytest.FixtureRequest, plc_client_kind: str) -> PLCConfig:
    expected_state = request.config.getoption("--plc-expected-cpu-state")
    return PLCConfig(
        host=request.config.getoption("--plc-ip"),
        port=request.config.getoption("--plc-port"),
        rack=request.config.getoption("--plc-rack"),
        slot=request.config.getoption("--plc-slot"),
        read_db=request.config.getoption("--plc-db-read"),
        write_db=request.config.getoption("--plc-db-write"),
        use_tls=request.config.getoption("--plc-use-tls"),
        tls_cert=request.config.getoption("--plc-tls-cert") or None,
        tls_key=request.config.getoption("--plc-tls-key") or None,
        tls_ca=request.config.getoption("--plc-tls-ca") or None,
        client_kind=plc_client_kind,
        password=os.environ.get(PASSWORD_ENV) or None,
        expected_cpu_state=expected_state or None,
    )


@pytest.fixture
def scenario_state() -> dict[str, Any]:
    return {}


@given("I am using a dedicated non-safety-critical test PLC")
def dedicated_plc() -> None:
    """The runbook makes this an explicit operator precondition."""


@given("the test configuration contains no secrets in reportable fields")
def reportable_fields_are_safe(request: pytest.FixtureRequest) -> None:
    sensitive_fragments = ("password", "secret", "private key", "plc ip", "hostname", "certificate path")
    values = (
        request.config.getoption("--plc-family"),
        request.config.getoption("--plc-model"),
        request.config.getoption("--plc-order-code"),
        request.config.getoption("--plc-firmware"),
        request.config.getoption("--plc-security-mode"),
        request.config.getoption("--plc-tia-configuration"),
    )
    assert not any(fragment in value.lower() for value in values for fragment in sensitive_fragments)
    password = os.environ.get(PASSWORD_ENV)
    if password:
        assert not any(password in value for value in values), "a reportable field contains the test password"


@given("the client uses the configured S7CommPlus security mode", target_fixture="plc_adapter")
def selected_adapter(plc_config: PLCConfig, request: pytest.FixtureRequest) -> PLCAdapter:
    # Looked up on the module so the CI dry run can substitute fake clients.
    adapter = support.make_adapter(plc_config)
    request.addfinalizer(adapter.close)
    return adapter


def _ensure_connected(adapter: PLCAdapter) -> None:
    if not adapter.is_connected():
        adapter.connect()


@when("I connect to the configured PLC")
@given("I am connected to the PLC")
def connect(plc_adapter: PLCAdapter) -> None:
    _ensure_connected(plc_adapter)


@then("the client reports that it is connected")
def reports_connected(plc_adapter: PLCAdapter) -> None:
    assert plc_adapter.is_connected()


@then("the negotiated protocol version and TLS mode are recorded")
def record_runtime_metadata(plc_adapter: PLCAdapter, request: pytest.FixtureRequest) -> None:
    _record(request, plc_adapter.runtime_metadata())


def _record(request: pytest.FixtureRequest, metadata: dict[str, Any]) -> None:
    request.config._real_plc_report.runtime_metadata.update(metadata)


@when("I disconnect")
def disconnect(plc_adapter: PLCAdapter) -> None:
    plc_adapter.disconnect()


@then("the client reports that it is disconnected")
def reports_disconnected(plc_adapter: PLCAdapter) -> None:
    assert not plc_adapter.is_connected()


@given("the non-optimized read-only DB has the documented canonical layout")
def canonical_layout(plc_adapter: PLCAdapter, plc_config: PLCConfig) -> None:
    _ensure_connected(plc_adapter)
    assert_canonical_fixture(plc_adapter.read(plc_config.read_db, 0, DB_SIZE))


@when("I read the complete fixture DB")
def read_complete_fixture(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    scenario_state["complete"] = plc_adapter.read(plc_config.read_db, 0, DB_SIZE)


@then("INT, REAL, BYTE, WORD, DWORD, DINT, CHAR and BOOL values match the fixture")
def complete_values_match(scenario_state: dict[str, Any]) -> None:
    assert_canonical_fixture(scenario_state["complete"])


@then("individual reads return the same values as the complete-block read")
def individual_values_match(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    complete = scenario_state["complete"]
    for offset, size in ((0, 2), (4, 4), (12, 1), (14, 2), (18, 4), (26, 4), (34, 1), (36, 1)):
        assert plc_adapter.read(plc_config.read_db, offset, size) == complete[offset : offset + size]


@when("I read values of different sizes in one multi-variable request")
def read_multiple(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    regions = ((0, 2), (4, 4), (12, 1), (18, 4), (34, 1), (36, 1))
    scenario_state["multi_regions"] = regions
    scenario_state["multi_values"] = plc_adapter.read_multi(plc_config.read_db, regions)


@then("every value matches the fixture")
def multiple_values_match(scenario_state: dict[str, Any]) -> None:
    expected = canonical_fixture_bytes()
    assert scenario_state["multi_values"] == [
        expected[offset : offset + size] for offset, size in scenario_state["multi_regions"]
    ]


@given("writing has been explicitly enabled")
def write_is_enabled(request: pytest.FixtureRequest) -> None:
    assert request.config.getoption("--allow-plc-write")


@given("I have a dedicated non-optimized scratch DB")
def scratch_db(plc_adapter: PLCAdapter, plc_config: PLCConfig) -> None:
    _ensure_connected(plc_adapter)
    if plc_config.read_db == plc_config.write_db:
        pytest.fail("scratch DB must differ from the read-only fixture DB")


@given(parsers.parse("the original bytes for {value_type} have been saved"))
def save_original(
    value_type: str,
    plc_adapter: PLCAdapter,
    plc_config: PLCConfig,
    scenario_state: dict[str, Any],
    request: pytest.FixtureRequest,
) -> None:
    offset, encoded, _, _ = WRITE_VALUES[value_type]
    guard = ScratchRestoreGuard(plc_adapter, plc_config.write_db, offset, len(encoded))
    scenario_state["guard"] = guard
    scenario_state["value_type"] = value_type
    request.addfinalizer(guard.restore)


@when(parsers.parse("I write a valid {value_type} value"))
def write_value(value_type: str, plc_adapter: PLCAdapter, plc_config: PLCConfig) -> None:
    offset, encoded, _, _ = WRITE_VALUES[value_type]
    plc_adapter.write(plc_config.write_db, offset, encoded)


@then("reading the address returns the written value")
def value_round_trips(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    offset, encoded, decoder, expected = WRITE_VALUES[scenario_state["value_type"]]
    actual = plc_adapter.read(plc_config.write_db, offset, len(encoded))
    assert decoder(actual) == expected


@then("the original bytes are restored and verified")
def original_is_restored(scenario_state: dict[str, Any]) -> None:
    scenario_state["guard"].restore()


@given("I connected to and disconnected from the PLC")
def connected_then_disconnected(plc_adapter: PLCAdapter) -> None:
    plc_adapter.connect()
    plc_adapter.disconnect()


@when("I reconnect with the same configuration")
def reconnect(plc_adapter: PLCAdapter) -> None:
    plc_adapter.connect()


@then("a known read succeeds")
def known_read_succeeds(plc_adapter: PLCAdapter, plc_config: PLCConfig) -> None:
    assert plc_adapter.read(plc_config.read_db, 0, 2) == canonical_fixture_bytes()[:2]


@when("I read the canonical fixture repeatedly")
def read_repeatedly(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    scenario_state["repeated"] = [plc_adapter.read(plc_config.read_db, 0, DB_SIZE) for _ in range(10)]


@then("every read succeeds with the expected value")
def repeated_reads_match(scenario_state: dict[str, Any]) -> None:
    for data in scenario_state["repeated"]:
        assert_canonical_fixture(data)


@then("disconnect completes cleanly")
def final_disconnect(plc_adapter: PLCAdapter) -> None:
    plc_adapter.disconnect()
    assert not plc_adapter.is_connected()


# --- CPU state -------------------------------------------------------------


@when("I read the CPU operating state")
def read_cpu_state(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    scenario_state["cpu_state"] = plc_adapter.cpu_state()


@then("the state is RUN, STOP or UNKNOWN and is recorded")
def cpu_state_recorded(scenario_state: dict[str, Any], plc_adapter: PLCAdapter, request: pytest.FixtureRequest) -> None:
    state = scenario_state["cpu_state"]
    assert state in ("RUN", "STOP", "UNKNOWN")
    _record(request, {f"cpu_state_{plc_adapter.client_kind}": state})


@then("the state matches the expected state when one is configured")
def cpu_state_matches(scenario_state: dict[str, Any], plc_config: PLCConfig) -> None:
    if plc_config.expected_cpu_state is not None:
        assert scenario_state["cpu_state"] == plc_config.expected_cpu_state


# --- Symbols ---------------------------------------------------------------


@when("I list the data blocks")
def list_datablocks(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    scenario_state["datablocks"] = plc_adapter.list_datablocks()


@then("the read-only fixture DB and the scratch DB are listed")
def fixture_dbs_listed(plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    numbers = {block.get("number") for block in scenario_state["datablocks"]}
    assert plc_config.read_db in numbers
    assert plc_config.write_db in numbers


@when("I browse the PLC symbols")
def browse_symbols(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    scenario_state["browsed"] = plc_adapter.browse()


@then("every member of the read-only fixture DB is listed with its type")
def fixture_members_browsed(plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    entries = fixture_entries(scenario_state["browsed"], plc_config.read_db)
    assert sorted(entries) == sorted(MEMBERS_BY_NAME)
    for name, entry in entries.items():
        assert entry["data_type"] == MEMBERS_BY_NAME[name].data_type, name


@then("the browsed byte offsets match the documented layout")
def browsed_offsets_match(plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    entries = fixture_entries(scenario_state["browsed"], plc_config.read_db)
    for member in FIXTURE_MEMBERS:
        entry = entries[member.name]
        assert entry["nonopt_address"] == member.offset, member.name
        if member.bit is not None:
            assert entry["nonopt_bitoffset"] == member.bit, member.name


@when("I read every fixture member by name")
def read_members_by_name(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    entries = fixture_entries(plc_adapter.browse(), plc_config.read_db)
    assert sorted(entries) == sorted(MEMBERS_BY_NAME), "not every fixture member was browsed"
    names = [entries[member.name]["name"] for member in FIXTURE_MEMBERS]
    results = plc_adapter.read_tags(names)
    scenario_state["named_results"] = dict(zip((member.name for member in FIXTURE_MEMBERS), results))
    scenario_state["complete"] = plc_adapter.read(plc_config.read_db, 0, DB_SIZE)


@then("every member read by name matches the byte-offset read")
def named_reads_match(scenario_state: dict[str, Any]) -> None:
    image = scenario_state["complete"]
    for name, result in scenario_state["named_results"].items():
        assert result.error is None, f"{name}: {result.error}"
        assert result.value == MEMBERS_BY_NAME[name].raw(image), name


@when(parsers.parse("I write a valid {value_type} value by name"))
def write_value_by_name(value_type: str, plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    member, raw = NAMED_WRITE_VALUES[value_type]
    entries = fixture_entries(plc_adapter.browse(), plc_config.write_db)
    assert member in entries, f"scratch DB member {member} was not browsed"
    scenario_state["named_member"] = entries[member]["name"]
    scenario_state["named_value"] = raw
    plc_adapter.write_tag(scenario_state["named_member"], raw)


@then("reading the member by name returns the written value")
def named_value_round_trips(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    (result,) = plc_adapter.read_tags([scenario_state["named_member"]])
    assert result.error is None, f"named read failed: {result.error}"
    assert result.value == scenario_state["named_value"]


# --- Subscriptions ---------------------------------------------------------


@given(parsers.parse("I know the access sequence of the {role} member {member}"))
def member_access_sequence(
    role: str, member: str, plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]
) -> None:
    _ensure_connected(plc_adapter)
    db_number = {"read-only": plc_config.read_db, "scratch": plc_config.write_db}[role]
    entries = fixture_entries(plc_adapter.browse(), db_number)
    assert member in entries, f"member {member} of DB{db_number} was not browsed"
    scenario_state["subscribed_member"] = MEMBERS_BY_NAME[member]
    scenario_state["subscribed_db"] = db_number
    scenario_state["access_sequence"] = entries[member]["access_sequence"]


@when("I subscribe to that member")
@given("I am subscribed to that member")
def subscribe(plc_adapter: PLCAdapter, scenario_state: dict[str, Any], request: pytest.FixtureRequest) -> None:
    subscription_id = plc_adapter.create_subscription([scenario_state["access_sequence"]])
    scenario_state["subscription_id"] = subscription_id

    def delete() -> None:
        if scenario_state.get("subscription_id") is not None and plc_adapter.is_connected():
            plc_adapter.delete_subscription(subscription_id)

    request.addfinalizer(delete)
    # The first notification carries the value at subscription time.
    scenario_state["first_notification"] = plc_adapter.receive_notification(subscription_id)


def _notified_value(notification: Any) -> bytes:
    assert not notification.errors, f"subscription item error: {notification.errors}"
    assert len(notification.values) == 1, notification.values
    value: bytes = next(iter(notification.values.values()))
    return value


@then("a notification carries its current value")
def notification_has_current_value(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    member = scenario_state["subscribed_member"]
    image = plc_adapter.read(scenario_state["subscribed_db"], 0, DB_SIZE)
    assert _notified_value(scenario_state["first_notification"]) == member.raw(image)


@then("a notification carries the written value")
def notification_has_written_value(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    _, expected, _, _ = WRITE_VALUES[scenario_state["value_type"]]
    deadline = time.monotonic() + NOTIFICATION_TIMEOUT
    seen: list[str] = []
    while time.monotonic() < deadline:
        value = _notified_value(plc_adapter.receive_notification(scenario_state["subscription_id"]))
        if value == expected:
            return
        seen.append(value.hex())
    pytest.fail(f"no notification carried {expected.hex()} within {NOTIFICATION_TIMEOUT}s; saw {seen}")


@then("the subscription is deleted cleanly")
def subscription_deleted(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    plc_adapter.delete_subscription(scenario_state.pop("subscription_id"))


# --- Alarms ----------------------------------------------------------------


@when("I read the active alarms")
def read_alarms(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    scenario_state["alarms"] = plc_adapter.read_alarms()


@then("the snapshot is a list of alarms and its size is recorded")
def alarms_recorded(plc_adapter: PLCAdapter, scenario_state: dict[str, Any], request: pytest.FixtureRequest) -> None:
    alarms = scenario_state["alarms"]
    assert isinstance(alarms, list)
    _record(request, {f"active_alarms_{plc_adapter.client_kind}": len(alarms)})


@when("I subscribe to alarms")
def subscribe_alarms(plc_adapter: PLCAdapter, scenario_state: dict[str, Any], request: pytest.FixtureRequest) -> None:
    subscription_id = plc_adapter.create_alarm_subscription()
    scenario_state["alarm_subscription_id"] = subscription_id

    def delete() -> None:
        if scenario_state.get("alarm_subscription_id") is not None and plc_adapter.is_connected():
            plc_adapter.delete_alarm_subscription(subscription_id)

    request.addfinalizer(delete)


@then("the alarm subscription is deleted cleanly")
def alarm_subscription_deleted(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    plc_adapter.delete_alarm_subscription(scenario_state.pop("alarm_subscription_id"))


# --- TLS and passwords -----------------------------------------------------


@given("TLS has been requested for this run")
def tls_requested(plc_config: PLCConfig) -> None:
    if not plc_config.use_tls:
        pytest.skip("TLS_NOT_REQUESTED: pass --plc-use-tls for a PLC with secure communication")


@then("the session reports TLS as active")
def tls_is_active(plc_adapter: PLCAdapter) -> None:
    assert plc_adapter.runtime_metadata()["tls_enabled"] is True


@when("I connect while trusting only a freshly generated CA")
def connect_untrusted_ca(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="s7-acceptance-") as directory:
        _attempt_connect(plc_adapter, scenario_state, tls_ca=untrusted_ca_certificate(Path(directory)))


def _attempt_connect(plc_adapter: PLCAdapter, scenario_state: dict[str, Any], **overrides: Any) -> None:
    scenario_state["connect_error"] = None
    try:
        plc_adapter.connect(**overrides)
    except (S7Error, ssl.SSLError, OSError) as error:
        scenario_state["connect_error"] = error


@then("the connection is refused")
def connection_refused(scenario_state: dict[str, Any]) -> None:
    assert scenario_state["connect_error"] is not None, "the PLC accepted the connection"


@given("a test password is configured")
def password_configured(plc_config: PLCConfig) -> None:
    if plc_config.password is None:
        pytest.skip(f"PASSWORD_NOT_CONFIGURED: set {PASSWORD_ENV} for a password-protected PLC")


@when("I connect with the configured password")
def connect_with_password(plc_adapter: PLCAdapter, plc_config: PLCConfig) -> None:
    plc_adapter.connect(password=plc_config.password)


@then("the protection level is recorded")
def protection_level_recorded(plc_adapter: PLCAdapter, request: pytest.FixtureRequest) -> None:
    level = plc_adapter.protection_level()
    assert level is not None, "the PLC reported no protection level"
    _record(request, {f"protection_level_{plc_adapter.client_kind}": level})


@when("I connect with a wrong password")
def connect_with_wrong_password(plc_adapter: PLCAdapter, plc_config: PLCConfig, scenario_state: dict[str, Any]) -> None:
    assert plc_config.password is not None
    _attempt_connect(plc_adapter, scenario_state, password=plc_config.password + "-wrong")


@then("the connection is refused as an authentication failure")
def refused_as_authentication_failure(scenario_state: dict[str, Any]) -> None:
    error = scenario_state["connect_error"]
    assert isinstance(error, S7AuthenticationError), f"expected S7AuthenticationError, got {type(error).__name__}"


# --- Features from open pull requests --------------------------------------


@given(parsers.parse("the client supports {feature}"))
def client_supports(feature: str, plc_adapter: PLCAdapter) -> None:
    key = feature.replace(" ", "_")
    if not plc_adapter.supports(key):
        pytest.skip(f"PENDING_FEATURE: needs {PENDING_FEATURES[key]}")


@when("I rebuild the session with reconnect()")
def rebuild_session(plc_adapter: PLCAdapter) -> None:
    plc_adapter.reconnect()


@given("I have recorded the PLC certificate fingerprint")
def record_fingerprint(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    _ensure_connected(plc_adapter)
    fingerprint = plc_adapter.peer_certificate_fingerprint()
    assert fingerprint is not None, "the client reported no PLC certificate"
    scenario_state["fingerprint"] = fingerprint.hex()
    plc_adapter.disconnect()


@when("I connect pinning that fingerprint")
def connect_pinned(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    plc_adapter.connect(tls_cert_fingerprint=scenario_state["fingerprint"])


@when("I connect pinning a different fingerprint")
def connect_wrong_pin(plc_adapter: PLCAdapter, scenario_state: dict[str, Any]) -> None:
    wrong = bytes(byte ^ 0xFF for byte in bytes.fromhex(scenario_state["fingerprint"])).hex()
    _attempt_connect(plc_adapter, scenario_state, tls_cert_fingerprint=wrong)
