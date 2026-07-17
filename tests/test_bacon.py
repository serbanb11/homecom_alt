"""Tests for the Bacon (Matter/MQTT device-shadow) helpers."""

import base64
import json
from typing import Any, Self

import pytest

from homecom_alt.bacon import (
    async_get_bacon_devices,
    decode_jwt_sub,
    generate_client_id,
)
from homecom_alt.exceptions import AuthFailedError


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
