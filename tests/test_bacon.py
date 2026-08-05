"""Tests for the Bacon (Matter/MQTT device-shadow) helpers."""

import asyncio
import base64
import json
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
