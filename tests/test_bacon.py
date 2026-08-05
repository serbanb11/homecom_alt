"""Tests for the Bacon (Matter/MQTT device-shadow) helpers."""

import asyncio
import base64
import json
import threading
from datetime import UTC, datetime
from typing import Any, Self

import pytest

from homecom_alt import bacon
from homecom_alt.bacon import (
    BaconMqttClient,
    async_get_bacon_devices,
    decode_jwt_exp,
    decode_jwt_sub,
    generate_client_id,
    parse_topic,
)
from homecom_alt.exceptions import (
    ApiError,
    AuthFailedError,
    MqttNotAuthorizedError,
)


def _make_jwt(payload: dict) -> str:
    """Build an unsigned JWT string with the given payload."""

    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'RS256'})}.{b64(payload)}.signature"


def test_decode_jwt_sub_ok() -> None:
    """The sub claim is returned."""
    token = _make_jwt({"sub": "f8569fbf-1234", "aud": ["bacon"]})
    assert decode_jwt_sub(token) == "f8569fbf-1234"


def test_decode_jwt_sub_invalid() -> None:
    """Malformed tokens yield None instead of raising."""
    assert decode_jwt_sub("not-a-jwt") is None
    assert decode_jwt_sub("") is None


def test_decode_jwt_exp_ok() -> None:
    """The exp claim is returned as an aware UTC datetime."""
    token = _make_jwt({"sub": "f8569fbf-1234", "exp": 1893456000})
    assert decode_jwt_exp(token) == datetime(2030, 1, 1, tzinfo=UTC)


def test_decode_jwt_exp_missing_or_invalid() -> None:
    """A missing, non-numeric or unparsable exp yields None instead of raising."""
    assert decode_jwt_exp(_make_jwt({"sub": "abc"})) is None
    assert decode_jwt_exp(_make_jwt({"exp": "soon"})) is None
    assert decode_jwt_exp("not-a-jwt") is None


def test_generate_client_id_is_64_hex() -> None:
    """The broker only accepts 64-char hex client ids."""
    cid = generate_client_id()
    assert len(cid) == 64
    int(cid, 16)  # raises if not hex
    assert cid != generate_client_id()


class _FakeResponse:
    def __init__(self, status: int, data: Any) -> None:
        self.status = status
        self._data = data

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def json(self) -> Any:
        return self._data


class _FakeSession:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.last_headers: dict | None = None

    def get(self, url: str, headers: dict | None = None) -> _FakeResponse:
        self.last_headers = headers
        return self._response


@pytest.mark.asyncio
async def test_async_get_bacon_devices_maps_serials() -> None:
    """Serials are mapped to the standard device dict shape."""
    session = _FakeSession(_FakeResponse(200, ["86DM-580-1", "86DM-580-2"]))
    devices = await async_get_bacon_devices(session, "token")
    assert devices == [
        {"deviceId": "86DM-580-1", "deviceType": "bacon_rac"},
        {"deviceId": "86DM-580-2", "deviceType": "bacon_rac"},
    ]
    assert session.last_headers["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_async_get_bacon_devices_unauthorized() -> None:
    """A 401 raises AuthFailedError."""
    session = _FakeSession(_FakeResponse(401, None))
    with pytest.raises(AuthFailedError):
        await async_get_bacon_devices(session, "token")


# ---------------------------------------------------------------------------
# BaconMqttClient.async_connect
# ---------------------------------------------------------------------------


class _FakeReasonCode:
    """Stand-in for paho's ReasonCode: a numeric value with a printable name."""

    def __init__(self, value: int, name: str) -> None:
        self.value = value
        self.name = name

    def __str__(self) -> str:
        return self.name


class _FakeMqttClient:
    """Minimal paho client double that replays a scripted CONNACK."""

    reason_code: Any = _FakeReasonCode(0, "Success")
    last: Any = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.init_args = args
        self.init_kwargs = kwargs
        self.on_connect: Any = None
        self.on_message: Any = None
        self.on_disconnect: Any = None
        self.credentials: tuple | None = None
        self.headers: dict | None = None
        self.subscriptions: list[str] = []
        self.published: list[tuple[str, Any]] = []
        self.loop_stopped = False
        _FakeMqttClient.last = self

    def ws_set_options(
        self, path: str | None = None, headers: dict | None = None
    ) -> None:
        self.ws_path = path
        self.headers = headers

    def username_pw_set(self, username: str, password: str | None = None) -> None:
        self.credentials = (username, password)

    def tls_set_context(self, context: Any) -> None:
        self.ssl_context = context

    def connect(self, host: str, port: int, keepalive: int = 60) -> None:
        self.target = (host, port, keepalive)

    def loop_start(self) -> None:
        """Deliver the scripted CONNACK the way paho's network thread would."""
        self.on_connect(self, None, {}, type(self).reason_code, None)

    def loop_stop(self) -> None:
        self.loop_stopped = True

    def disconnect(self) -> None:
        self.disconnected = True

    def subscribe(self, topic: str) -> None:
        self.subscriptions.append(topic)

    def publish(self, topic: str, payload: Any = None) -> None:
        self.published.append((topic, payload))


def _install_fake_mqtt(
    monkeypatch: pytest.MonkeyPatch, reason_code: Any
) -> type[_FakeMqttClient]:
    """Patch paho's Client with the double, answering with ``reason_code``."""
    monkeypatch.setattr(_FakeMqttClient, "reason_code", reason_code)
    monkeypatch.setattr(bacon.mqtt, "Client", _FakeMqttClient)
    return _FakeMqttClient


@pytest.mark.asyncio
async def test_async_connect_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful CONNACK subscribes the user namespace and records the token."""
    fake = _install_fake_mqtt(monkeypatch, _FakeReasonCode(0, "Success"))
    token = _make_jwt({"sub": "sub-1", "exp": 1893456000})
    client = BaconMqttClient("a" * 64)

    await client.async_connect(token, "sub-1")

    assert client.is_connected is True
    assert fake.last.subscriptions == ["users/sub-1/#"]
    assert fake.last.credentials == ("sub-1", token)
    assert client.token_expires_at == datetime(2030, 1, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_async_connect_disables_paho_auto_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Paho must never re-dial itself: it would replay a refused access token."""
    fake = _install_fake_mqtt(monkeypatch, _FakeReasonCode(0, "Success"))
    client = BaconMqttClient("a" * 64)

    await client.async_connect(_make_jwt({"sub": "sub-1"}), "sub-1")

    assert fake.last.init_kwargs["reconnect_on_failure"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason_code",
    [
        _FakeReasonCode(135, "Not authorized"),
        _FakeReasonCode(134, "Bad user name or password"),
        _FakeReasonCode(135, "ReasonCode 135"),
    ],
    ids=["not-authorized", "bad-credentials", "numeric-only"],
)
async def test_async_connect_credential_refusal_is_transport_error(
    monkeypatch: pytest.MonkeyPatch, reason_code: Any
) -> None:
    """A refused password is a transport failure, never an AuthFailedError.

    The MQTT password is the access token, so this means "reconnect with a fresh
    token", not "the OAuth refresh token is dead" — mapping it onto
    AuthFailedError is what used to trigger a spurious reauth. It must also be
    raised as soon as the CONNACK lands instead of after the 15 s timeout.
    """
    _install_fake_mqtt(monkeypatch, reason_code)
    client = BaconMqttClient("a" * 64)

    with pytest.raises(MqttNotAuthorizedError) as excinfo:
        async with asyncio.timeout(5):
            await client.async_connect(_make_jwt({"sub": "sub-1"}), "sub-1")

    assert not isinstance(excinfo.value, AuthFailedError)
    assert client.is_connected is False


@pytest.mark.asyncio
async def test_async_connect_other_refusal_is_plain_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refusals unrelated to credentials stay generic ApiErrors."""
    _install_fake_mqtt(monkeypatch, _FakeReasonCode(151, "Quota exceeded"))
    client = BaconMqttClient("a" * 64)

    with pytest.raises(ApiError) as excinfo:
        async with asyncio.timeout(5):
            await client.async_connect(_make_jwt({"sub": "sub-1"}), "sub-1")

    assert not isinstance(excinfo.value, MqttNotAuthorizedError)


def test_token_expires_at_without_session() -> None:
    """No connect attempt yet → no known expiry."""
    assert BaconMqttClient("a" * 64).token_expires_at is None


# ---------------------------------------------------------------------------
# parse_topic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("topic", "expected"),
    [
        (
            "users/sub-1/devices/86DM-1/shadows/state/get/accepted",
            ("86DM-1", "shadows", "state/get/accepted"),
        ),
        (
            "users/sub-1/devices/86DM-1/topics/sensor",
            ("86DM-1", "topics", "sensor"),
        ),
        (
            "users/sub-1/devices/86DM-1/commands/export",
            ("86DM-1", "commands", "export"),
        ),
        # Account-level: no devices/ segment, so no serial.
        ("users/sub-1/commands/export", (None, "commands", "export")),
    ],
)
def test_parse_topic_forms(topic: str, expected: tuple) -> None:
    """Both the device and the account topic shapes are split correctly."""
    assert tuple(parse_topic(topic)) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "topic", ["", "users", "users/sub-1", "nope/sub-1/devices/x/y"]
)
def test_parse_topic_rejects_foreign_topics(topic: str) -> None:
    """Anything that is not a bacon topic is rejected rather than raising."""
    assert parse_topic(topic) is None


# ---------------------------------------------------------------------------
# topics/* capture — the channel that carries roomTemperature
# ---------------------------------------------------------------------------


class _FakeMessage:
    """Stand-in for paho's MQTTMessage."""

    def __init__(self, topic: str, payload: Any) -> None:
        self.topic = topic
        self.payload = (
            payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        )


async def _connected_client(monkeypatch: pytest.MonkeyPatch) -> BaconMqttClient:
    """Return a client with a live fake session, ready to receive messages."""
    _install_fake_mqtt(monkeypatch, _FakeReasonCode(0, "Success"))
    client = BaconMqttClient("a" * 64)
    await client.async_connect(_make_jwt({"sub": "sub-1"}), "sub-1")
    return client


def _deliver(client: BaconMqttClient, topic: str, payload: Any) -> None:
    """Feed a message in the way paho's network thread would."""
    client._on_message(None, None, _FakeMessage(topic, payload))


@pytest.mark.asyncio
async def test_sensor_topic_is_captured_not_discarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RoomTemperature arrives on topics/sensor and must survive the demux.

    This is the whole point of the change: the payload was previously dropped
    because it is not a shadow reply, which is why current_temperature was
    unobtainable.
    """
    client = await _connected_client(monkeypatch)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/topics/sensor",
        {"deviceType": "rac", "items": [{"timestamp": 1, "roomTemperature": 24.5}]},
    )

    assert client.get_sensor("86DM-1") == {"timestamp": 1, "roomTemperature": 24.5}


@pytest.mark.asyncio
async def test_sensor_returns_latest_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """The newest item of the batch wins."""
    client = await _connected_client(monkeypatch)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/topics/sensor",
        {"items": [{"roomTemperature": 20.0}, {"roomTemperature": 22.5}]},
    )

    assert client.get_sensor("86DM-1") == {"roomTemperature": 22.5}


@pytest.mark.asyncio
async def test_meta_and_info_topics_are_captured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Meta and info are cached alongside sensor."""
    client = await _connected_client(monkeypatch)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/topics/meta",
        {"operationMode": {"enum": ["cool", "heat"], "ro": False}},
    )
    _deliver(
        client,
        "users/sub-1/devices/86DM-1/topics/info",
        {"online": True, "firmwareVersion": "1.2.3"},
    )

    assert client.get_metadata("86DM-1") == {
        "operationMode": {"enum": ["cool", "heat"], "ro": False}
    }
    assert client.get_info("86DM-1") == {"online": True, "firmwareVersion": "1.2.3"}


@pytest.mark.asyncio
async def test_accessors_are_none_before_any_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """topics/* cannot be polled, so nothing is known until the device pushes."""
    client = await _connected_client(monkeypatch)

    assert client.get_sensor("86DM-1") is None
    assert client.get_metadata("86DM-1") is None
    assert client.get_info("86DM-1") is None


@pytest.mark.asyncio
async def test_malformed_sensor_payloads_do_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent/odd shapes yield None rather than an exception."""
    client = await _connected_client(monkeypatch)
    topic = "users/sub-1/devices/86DM-1/topics/sensor"

    for payload in ({"items": []}, {"items": "nope"}, {"no_items": 1}, [1, 2]):
        _deliver(client, topic, payload)
        assert client.get_sensor("86DM-1") is None


@pytest.mark.asyncio
async def test_raw_snapshot_records_topic_and_arrival_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every channel lands in the snapshot with an ISO timestamp."""
    client = await _connected_client(monkeypatch)

    _deliver(client, "users/sub-1/devices/86DM-1/topics/sensor", {"items": []})
    _deliver(client, "users/sub-1/commands/export", {"ok": True})

    snapshot = client.raw_snapshot()
    assert "86DM-1/topics/sensor" in snapshot
    # Account-level topics have no serial.
    assert "-/commands/export" in snapshot
    datetime.fromisoformat(snapshot["86DM-1/topics/sensor"]["received_at"])


@pytest.mark.asyncio
async def test_raw_snapshot_caps_oversized_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gzip+base64 blob is replaced by its size, not stored whole."""
    client = await _connected_client(monkeypatch)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/shadows/state/update/documents",
        {"schedules": "x" * 50_000},
    )

    stored = client.raw_snapshot()["86DM-1/shadows/state/update/documents"]["payload"]
    assert stored["schedules"] == {"__truncated__": 50_000}


def test_raw_snapshot_thread_safe_during_concurrent_caching() -> None:
    """raw_snapshot() must not raise while messages land on the paho thread.

    ``_cache_raw`` runs on paho's network thread and ``raw_snapshot`` on the
    event loop. Each delivered message here uses a fresh serial, so the cache
    keeps growing; without a lock the snapshot's ``sorted(self._raw.items())``
    would hit "dictionary changed size during iteration".
    """
    client = BaconMqttClient("a" * 64)
    inserts = 3000
    errors: list[BaseException] = []

    def writer() -> None:
        for i in range(inserts):
            try:
                _deliver(
                    client,
                    f"users/sub-1/devices/dev-{i}/topics/sensor",
                    {"items": [{"i": i}]},
                )
            except BaseException as err:  # noqa: BLE001 - surfaced to the test
                errors.append(err)
                return

    thread = threading.Thread(target=writer)
    thread.start()
    # Snapshot continuously while the cache keeps gaining new keys, so the
    # snapshot's iteration overlaps a mutation on the writer thread.
    while thread.is_alive():
        assert isinstance(client.raw_snapshot(), dict)
    thread.join()

    assert not errors
    assert len(client.raw_snapshot()) == inserts


@pytest.mark.asyncio
async def test_undecodable_payload_is_kept_as_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-JSON body is still recorded so the topic is not silently lost."""
    client = await _connected_client(monkeypatch)

    _deliver(client, "users/sub-1/devices/86DM-1/topics/sensor", b"\xff not json")

    payload = client.raw_snapshot()["86DM-1/topics/sensor"]["payload"]
    assert "__raw__" in payload


@pytest.mark.asyncio
async def test_raw_listener_sees_every_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """register_raw_listener fires for shadow and topics alike."""
    client = await _connected_client(monkeypatch)
    seen: list[tuple] = []
    client.register_raw_listener(lambda s, p, _payload: seen.append((s, p)))

    _deliver(client, "users/sub-1/devices/86DM-1/topics/sensor", {"items": []})
    _deliver(
        client,
        "users/sub-1/devices/86DM-1/shadows/state/get/accepted",
        {"state": {"reported": {}, "desired": {}}},
    )
    await asyncio.sleep(0)  # let call_soon_threadsafe callbacks run

    assert ("86DM-1", "topics/sensor") in seen
    assert ("86DM-1", "shadows/state/get/accepted") in seen


# ---------------------------------------------------------------------------
# regression guards for the shadow behaviour the demux must not disturb
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_get_accepted_resolves_a_pending_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """update/accepted may be a partial delta and must not answer a get."""
    client = await _connected_client(monkeypatch)
    task = asyncio.ensure_future(client.async_get_state("86DM-1", timeout=5))
    await asyncio.sleep(0)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/shadows/state/update/accepted",
        {"state": {"reported": {"powerEnabled": True}}},
    )
    await asyncio.sleep(0)
    assert not task.done()

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/shadows/state/get/accepted",
        {"state": {"reported": {"tempSetpoint": 21}, "desired": {}}},
    )
    assert await task == {"reported": {"tempSetpoint": 21}, "desired": {}}


@pytest.mark.asyncio
async def test_get_rejected_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rejected shadow get keeps failing the pending read."""
    client = await _connected_client(monkeypatch)
    task = asyncio.ensure_future(client.async_get_state("86DM-1", timeout=5))
    await asyncio.sleep(0)

    _deliver(client, "users/sub-1/devices/86DM-1/shadows/state/get/rejected", {})

    with pytest.raises(ApiError):
        await task


@pytest.mark.asyncio
async def test_topics_message_does_not_resolve_a_shadow_get(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capturing topics/* must not leak into the shadow request/response path."""
    client = await _connected_client(monkeypatch)
    task = asyncio.ensure_future(client.async_get_state("86DM-1", timeout=5))
    await asyncio.sleep(0)

    _deliver(
        client,
        "users/sub-1/devices/86DM-1/topics/sensor",
        {"items": [{"roomTemperature": 24.5}]},
    )
    await asyncio.sleep(0)

    assert not task.done()
    task.cancel()
