"""Tests for HomeComAlt module."""
# pylint: disable=protected-access

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import jwt
import pytest
from aiohttp import ClientConnectorError, ClientResponseError, ClientSession

from homecom_alt import (
    ApiError,
    AuthFailedError,
    ConnectionOptions,
    HomeComAlt,
    HomeComGeneric,
    HomeComK40,
    HomeComRac,
    HomeComWddw2,
    InvalidSensorDataError,
    NotRespondingError,
)
from homecom_alt.const import (
    JSON,
    OAUTH_DOMAIN,
    OAUTH_ENDPOINT,
    OAUTH_PARAMS,
    OAUTH_PARAMS_BUDERUS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def create_test_jwt(expiration: int = 9999999999) -> str:
    """Create a valid JWT token for testing."""
    secret = "test_secret_key"
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "exp": expiration,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


DEVICE_ID = "test-device-123"


def _make_options(**overrides):  # noqa: ANN003, ANN202
    defaults = {
        "username": "test_user",
        "token": create_test_jwt(),
        "refresh_token": "test_refresh",
        "code": "test_code",
    }
    defaults.update(overrides)
    return ConnectionOptions(**defaults)


def _mock_json_response(data, status=HTTPStatus.OK):  # noqa: ANN001, ANN202
    """Return an AsyncMock that behaves like an aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=data)
    return resp


# ===========================================================================
# Base class - HTTP layer (existing tests, kept as-is with minor DRY-up)
# ===========================================================================


@pytest.mark.asyncio
async def test_async_http_request_success_json() -> None:
    """Test that _async_http_request returns a successful response for JSON requests."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = _mock_json_response({"key": "value"})
        mock_request.return_value = mock_response

        resp = await bhc._async_http_request("get", "http://test.com", req_type=1)
        assert resp.status == HTTPStatus.OK

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_success_form() -> None:
    """Test that _async_http_request returns a successful response for form requests."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = _mock_json_response({"key": "value"})
        mock_request.return_value = mock_response

        resp = await bhc._async_http_request("get", "http://test.com", req_type=2)
        assert resp.status == HTTPStatus.OK

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_unauthorized() -> None:
    """Test that _async_http_request raises AuthFailedError on 401 response."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.UNAUTHORIZED
        )
        with pytest.raises(AuthFailedError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_bad_request() -> None:
    """Test that _async_http_request returns None for a BAD_REQUEST on the token URL."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.BAD_REQUEST
        )
        response = await bhc._async_http_request(
            "post", "https://singlekey-id.com/auth/connect/token"
        )
        assert response is None

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_not_found_returns_empty_dict() -> None:
    """Test that HTTP 404 returns empty dict (unsupported endpoint)."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.NOT_FOUND
        )
        response = await bhc._async_http_request("get", "http://test.com/missing")
        assert response == {}

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_other_client_error_raises_api_error() -> None:
    """Test that non-special HTTP errors raise ApiError."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.FORBIDDEN
        )
        with pytest.raises(ApiError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_timeout() -> None:
    """Test that _async_http_request raises NotRespondingError on connection timeout."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientConnectorError(None, OSError())
        with pytest.raises(NotRespondingError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_timeout_error() -> None:
    """Test that TimeoutError raises NotRespondingError."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = TimeoutError()
        with pytest.raises(NotRespondingError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_invalid_status() -> None:
    """Test that ApiError for HTTP errors other than 200/204."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.INTERNAL_SERVER_ERROR
        mock_request.return_value = mock_response
        with pytest.raises(ApiError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_no_content_success() -> None:
    """Test 204 NO_CONTENT is accepted."""
    session = ClientSession()
    options = _make_options()
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.NO_CONTENT
        mock_request.return_value = mock_response
        resp = await bhc._async_http_request("put", "http://test.com")
        assert resp.status == HTTPStatus.NO_CONTENT

    await session.close()


# ===========================================================================
# _to_data
# ===========================================================================


@pytest.mark.asyncio
async def test_to_data_none_response() -> None:
    """None → None."""
    result = await HomeComAlt._to_data(None)
    assert result is None


@pytest.mark.asyncio
async def test_to_data_empty_response() -> None:
    """Falsy (empty dict / 0 / '') → None."""
    result = await HomeComAlt._to_data({})
    assert result is None


@pytest.mark.asyncio
async def test_to_data_valid_json() -> None:
    """Valid json response → parsed dict."""
    resp = _mock_json_response({"temp": 21.5})
    result = await HomeComAlt._to_data(resp)
    assert result == {"temp": 21.5}


@pytest.mark.asyncio
async def test_to_data_value_error() -> None:
    """ValueError from json() → InvalidSensorDataError."""
    resp = AsyncMock()
    resp.json = AsyncMock(side_effect=ValueError("bad"))
    # resp is truthy
    resp.__bool__ = lambda self: True  # noqa: ARG005
    with pytest.raises(InvalidSensorDataError):
        await HomeComAlt._to_data(resp)


# ===========================================================================
# Property getters / setters
# ===========================================================================


@pytest.mark.asyncio
async def test_token_property() -> None:
    """Test token property getter and setter."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=True)
    original = bhc.token
    assert original is not None
    bhc.token = "new_token"
    assert bhc.token == "new_token"
    await session.close()


@pytest.mark.asyncio
async def test_refresh_token_property() -> None:
    """Test refresh token property getter and setter."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=True)
    assert bhc.refresh_token == "test_refresh"
    bhc.refresh_token = "new_refresh"
    assert bhc.refresh_token == "new_refresh"
    await session.close()


# ===========================================================================
# check_jwt
# ===========================================================================


@pytest.mark.asyncio
async def test_check_jwt_valid() -> None:
    """Test that check_jwt returns True for a valid, unexpired token."""
    session = ClientSession()
    options = _make_options()
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)
    assert homecom_alt.check_jwt() is True
    await session.close()


@pytest.mark.asyncio
async def test_check_jwt_invalid() -> None:
    """Test that check_jwt returns False for an expired token."""
    session = ClientSession()
    options = _make_options()
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)
    homecom_alt._options.token = create_test_jwt(
        expiration=int((datetime.now(UTC) - timedelta(days=1)).timestamp())
    )
    assert homecom_alt.check_jwt() is False
    await session.close()


@pytest.mark.asyncio
async def test_check_jwt_no_token() -> None:
    """No token → False."""
    session = ClientSession()
    bhc = HomeComAlt(session, ConnectionOptions(), auth_provider=True)
    assert bhc.check_jwt() is False
    await session.close()


@pytest.mark.asyncio
async def test_check_jwt_decode_error() -> None:
    """Corrupted token → False."""
    session = ClientSession()
    bhc = HomeComAlt(session, ConnectionOptions(token="not.a.jwt"), auth_provider=True)
    assert bhc.check_jwt() is False
    await session.close()


# ===========================================================================
# get_token
# ===========================================================================


@pytest.mark.asyncio
async def test_get_token_valid_jwt() -> None:
    """Test that get_token returns None if the JWT is still valid."""
    session = ClientSession()
    options = _make_options()
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(homecom_alt, "check_jwt", return_value=True):
        assert await homecom_alt.get_token() is None

    await session.close()


@pytest.mark.asyncio
async def test_get_token_auth_provider_false() -> None:
    """auth_provider=False → returns None immediately."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    result = await bhc.get_token()
    assert result is None
    await session.close()


@pytest.mark.asyncio
async def test_get_token_refresh_success() -> None:
    """Refresh token path succeeds."""
    session = ClientSession()
    options = _make_options()
    bhc = HomeComAlt(session, options, auth_provider=True)

    mock_resp = _mock_json_response(
        {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
        }
    )

    with (
        patch.object(bhc, "check_jwt", return_value=False),
        patch.object(bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)),
    ):
        result = await bhc.get_token()
        assert result is True
        assert bhc.token == "new_access"
        assert bhc.refresh_token == "new_refresh"

    await session.close()


@pytest.mark.asyncio
async def test_get_token_refresh_returns_none_falls_through_to_code() -> None:
    """Refresh returns None, then code exchange succeeds."""
    session = ClientSession()
    options = _make_options()
    bhc = HomeComAlt(session, options, auth_provider=True)

    validate_result = {"access_token": "code_access", "refresh_token": "code_refresh"}

    with (
        patch.object(bhc, "check_jwt", return_value=False),
        patch.object(bhc, "_async_http_request", new=AsyncMock(return_value=None)),
        patch.object(bhc, "validate_auth", new=AsyncMock(return_value=validate_result)),
    ):
        result = await bhc.get_token()
        assert result is True
        assert bhc.token == "code_access"
        assert bhc.refresh_token == "code_refresh"
        assert bhc._options.code is None

    await session.close()


@pytest.mark.asyncio
async def test_get_token_all_fail_raises_auth_failed() -> None:
    """Both refresh and code exchange fail → AuthFailedError."""
    session = ClientSession()
    options = _make_options(refresh_token=None, code=None)
    bhc = HomeComAlt(session, options, auth_provider=True)

    with (
        patch.object(bhc, "check_jwt", return_value=False),
        patch.object(bhc, "_async_http_request", new=AsyncMock(return_value=None)),
        pytest.raises(AuthFailedError),
    ):
        await bhc.get_token()

    await session.close()


# ===========================================================================
# validate_auth
# ===========================================================================


@pytest.mark.asyncio
async def test_validate_auth_success() -> None:
    """Test that validate_auth exchanges a code for access and refresh tokens."""
    session = ClientSession()
    homecom = HomeComAlt(
        session, ConnectionOptions(code="test_code"), auth_provider=True
    )

    with patch.object(homecom, "_async_http_request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value={
                "access_token": "test_token",
                "refresh_token": "refresh_token",
            }
        )
        mock_request.return_value = mock_response

        token = await homecom.validate_auth("auth_code", "code_verifier")
        assert token == {"access_token": "test_token", "refresh_token": "refresh_token"}

        mock_request.assert_called_once_with(
            "post",
            OAUTH_DOMAIN + OAUTH_ENDPOINT,
            "code=auth_code&"
            + urlencode(OAUTH_PARAMS)
            + "&code_verifier=code_verifier",
            2,
        )

    await session.close()


@pytest.mark.asyncio
async def test_validate_auth_invalid_response() -> None:
    """Test AuthFailedError if the response is invalid JSON."""
    session = ClientSession()
    homecom = HomeComAlt(
        session, ConnectionOptions(code="test_code"), auth_provider=True
    )

    with patch.object(homecom, "_async_http_request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(side_effect=ValueError("Invalid JSON"))
        mock_request.return_value = mock_response

        with pytest.raises(AuthFailedError, match="Authorization has failed"):
            await homecom.validate_auth("auth_code", "code_verifier")

    await session.close()


# ===========================================================================
# async_get_devices
# ===========================================================================


@pytest.mark.asyncio
async def test_async_get_devices_success() -> None:
    """Test async_get_devices returns device list."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)

    mock_resp = MagicMock()
    mock_resp.json = MagicMock(return_value=[{"id": "gw1"}])

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_devices()
        assert result == [{"id": "gw1"}]

    await session.close()


# ===========================================================================
# Simple base-class getters
# ===========================================================================


@pytest.mark.asyncio
async def test_async_get_firmware() -> None:
    """Test async_get_firmware returns firmware data."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"version": "1.2.3"})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_firmware(DEVICE_ID)
        assert result == {"version": "1.2.3"}

    await session.close()


@pytest.mark.asyncio
async def test_async_get_notifications() -> None:
    """Test async_get_notifications returns notification data."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"values": [{"msg": "alert"}]})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_notifications(DEVICE_ID)
        assert result == {"values": [{"msg": "alert"}]}

    await session.close()


@pytest.mark.asyncio
async def test_async_get_system_info() -> None:
    """Test async_get_system_info returns system info."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"brand": "Bosch"})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_system_info(DEVICE_ID)
        assert result == {"brand": "Bosch"}

    await session.close()


@pytest.mark.asyncio
async def test_async_get_pv_list() -> None:
    """Test async_get_pv_list returns point value list."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"references": []})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_pv_list(DEVICE_ID)
        assert result == {"references": []}

    await session.close()


# ===========================================================================
# async_get_time (fallback logic)
# ===========================================================================


@pytest.mark.asyncio
async def test_async_get_time_first_endpoint_success() -> None:
    """First time endpoint works → return data."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"value": "2024-01-01T00:00:00"})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_get_time(DEVICE_ID)
        assert result == {"value": "2024-01-01T00:00:00"}

    await session.close()


@pytest.mark.asyncio
async def test_async_get_time_first_fails_second_succeeds() -> None:
    """First endpoint returns empty dict (404), second succeeds."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"value": "2024-06-01T12:00:00"})

    call_count = 0

    async def side_effect(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202, ARG001
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {}  # 404 mapped to empty dict
        return mock_resp

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(side_effect=side_effect)
    ):
        result = await bhc.async_get_time(DEVICE_ID)
        assert result == {"value": "2024-06-01T12:00:00"}

    await session.close()


@pytest.mark.asyncio
async def test_async_get_time_both_fail() -> None:
    """Both endpoints fail → raises last exception."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)

    async def side_effect(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202, ARG001
        return {}

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(side_effect=side_effect)
    ), pytest.raises(ApiError):
        await bhc.async_get_time(DEVICE_ID)

    await session.close()


@pytest.mark.asyncio
async def test_async_get_time_auth_failed_reraises() -> None:
    """AuthFailedError is re-raised immediately, not caught."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)

    with patch.object(
        bhc,
        "_async_http_request",
        new=AsyncMock(side_effect=AuthFailedError("auth")),
    ), pytest.raises(AuthFailedError):
        await bhc.async_get_time(DEVICE_ID)

    await session.close()


# ===========================================================================
# async_action_universal_get
# ===========================================================================


@pytest.mark.asyncio
async def test_async_action_universal_get() -> None:
    """Test async_action_universal_get returns endpoint data."""
    session = ClientSession()
    bhc = HomeComAlt(session, _make_options(), auth_provider=False)
    mock_resp = _mock_json_response({"value": 42})

    with patch.object(
        bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)
    ):
        result = await bhc.async_action_universal_get(DEVICE_ID, "/some/path")
        assert result == {"value": 42}

    await session.close()


# ===========================================================================
# HomeComGeneric
# ===========================================================================


@pytest.mark.asyncio
async def test_generic_async_update() -> None:
    """Test HomeComGeneric async_update returns device data."""
    session = ClientSession()
    dev = HomeComGeneric(session, _make_options(), DEVICE_ID, auth_provider=False)

    result = await dev.async_update(DEVICE_ID)
    assert result.device == DEVICE_ID
    assert result.firmware == []
    assert result.notifications == []

    await session.close()


# ===========================================================================
# HomeComRac
# ===========================================================================


def _make_rac(session):  # noqa: ANN001, ANN202
    return HomeComRac(session, _make_options(), DEVICE_ID, auth_provider=False)


@pytest.mark.asyncio
async def test_rac_async_update() -> None:
    """Test RAC async_update returns populated device data."""
    session = ClientSession()
    rac = _make_rac(session)

    notifications_resp = _mock_json_response({"values": [{"code": 1}]})
    standard_resp = _mock_json_response({"references": [{"id": "s1"}]})
    advanced_resp = _mock_json_response({"references": [{"id": "a1"}]})
    switch_resp = _mock_json_response({"references": [{"id": "sw1"}]})


    async def route_request(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001
        if "notifications" in url:
            return notifications_resp
        if "standardFunctions" in url:
            return standard_resp
        if "advancedFunctions" in url:
            return advanced_resp
        if "switchPrograms/list" in url:
            return switch_resp
        return _mock_json_response({})

    with patch.object(
        rac, "_async_http_request", new=AsyncMock(side_effect=route_request)
    ):
        result = await rac.async_update(DEVICE_ID)

    assert result.device == DEVICE_ID
    assert result.stardard_functions == [{"id": "s1"}]
    assert result.advanced_functions == [{"id": "a1"}]
    assert result.switch_programs == [{"id": "sw1"}]
    assert result.notifications == [{"code": 1}]

    await session.close()


@pytest.mark.asyncio
async def test_rac_async_control() -> None:
    """Test RAC async_control sends put request with value."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_control(DEVICE_ID, "on")
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][0] == "put"
        assert call_args[0][2] == {"value": "on"}
        assert call_args[0][3] == JSON

    await session.close()


@pytest.mark.asyncio
async def test_rac_async_turn_on() -> None:
    """Test RAC async_turn_on sends on control."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "async_control", new=AsyncMock()) as mock_ctrl:
        await rac.async_turn_on(DEVICE_ID)
        mock_ctrl.assert_called_once_with(DEVICE_ID, "on")

    await session.close()


@pytest.mark.asyncio
async def test_rac_async_turn_off() -> None:
    """Test RAC async_turn_off sends off control."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "async_control", new=AsyncMock()) as mock_ctrl:
        await rac.async_turn_off(DEVICE_ID)
        mock_ctrl.assert_called_once_with(DEVICE_ID, "off")

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_temperature_rounds() -> None:
    """Test RAC set temperature rounds to nearest 0.5."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_temperature(DEVICE_ID, 22.456)
        call_args = mock_req.call_args
        assert call_args[0][2] == {"value": 22.5}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_hvac_mode_off() -> None:
    """'off' mode sends 'off' control."""
    session = ClientSession()
    rac = _make_rac(session)

    with (
        patch.object(rac, "async_control", new=AsyncMock()) as mock_ctrl,
        patch.object(rac, "_async_http_request", new=AsyncMock()),
    ):
        await rac.async_set_hvac_mode(DEVICE_ID, "off")
        mock_ctrl.assert_called_once_with(DEVICE_ID, "off")

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_hvac_mode_heating() -> None:
    """Non-off mode sends 'on' control then sets mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with (
        patch.object(rac, "async_control", new=AsyncMock()) as mock_ctrl,
        patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req,
    ):
        await rac.async_set_hvac_mode(DEVICE_ID, "heating")
        mock_ctrl.assert_called_once_with(DEVICE_ID, "on")
        assert mock_req.call_args[0][2] == {"value": "heating"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_plasmacluster_true() -> None:
    """Test RAC set plasmacluster to on when True."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_plasmacluster(DEVICE_ID, True)  # noqa: FBT003
        assert mock_req.call_args[0][2] == {"value": "on"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_plasmacluster_false() -> None:
    """Test RAC set plasmacluster to off when False."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_plasmacluster(DEVICE_ID, False)  # noqa: FBT003
        assert mock_req.call_args[0][2] == {"value": "off"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_boost() -> None:
    """Test RAC set boost mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_boost(DEVICE_ID, True)  # noqa: FBT003
        assert mock_req.call_args[0][2] == {"value": "on"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_eco() -> None:
    """Test RAC set eco mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_eco(DEVICE_ID, False)  # noqa: FBT003
        assert mock_req.call_args[0][2] == {"value": "off"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_fan_mode() -> None:
    """Test RAC set fan mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_fan_mode(DEVICE_ID, "high")
        assert mock_req.call_args[0][2] == {"value": "high"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_vertical_swing() -> None:
    """Test RAC set vertical swing mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_vertical_swing_mode(DEVICE_ID, "swing")
        assert mock_req.call_args[0][2] == {"value": "swing"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_set_horizontal_swing() -> None:
    """Test RAC set horizontal swing mode."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_set_horizontal_swing_mode(DEVICE_ID, "auto")
        assert mock_req.call_args[0][2] == {"value": "auto"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_switch_program() -> None:
    """Test RAC switch program."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_switch_program(DEVICE_ID, "prog1")
        assert mock_req.call_args[0][2] == {"value": "prog1"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_control_program() -> None:
    """Test RAC control program."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_control_program(DEVICE_ID, "on")
        assert mock_req.call_args[0][2] == {"value": "on"}

    await session.close()


@pytest.mark.asyncio
async def test_rac_time_on() -> None:
    """Test RAC time on setting."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_time_on(DEVICE_ID, 30)
        assert mock_req.call_args[0][2] == {"value": 30}
        assert "/on" in mock_req.call_args[0][1]

    await session.close()


@pytest.mark.asyncio
async def test_rac_time_off() -> None:
    """Test RAC time off setting."""
    session = ClientSession()
    rac = _make_rac(session)

    with patch.object(rac, "_async_http_request", new=AsyncMock()) as mock_req:
        await rac.async_time_off(DEVICE_ID, 60)
        assert mock_req.call_args[0][2] == {"value": 60}
        assert "/off" in mock_req.call_args[0][1]

    await session.close()


# ===========================================================================
# HomeComK40
# ===========================================================================


def _make_k40(session):  # noqa: ANN001, ANN202
    return HomeComK40(session, _make_options(), DEVICE_ID, auth_provider=False)


@pytest.mark.asyncio
async def test_k40_async_update_with_dhw_and_hc() -> None:  # noqa: C901, PLR0915
    """Test full K40 update with DHW and HC circuits."""
    session = ClientSession()
    k40 = _make_k40(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001, C901, PLR0911, PLR0912
        if "notifications" in url:
            return _mock_json_response({"values": []})
        if "dhwCircuits" in url and "operationMode" in url:
            return _mock_json_response({"value": "auto"})
        if "dhwCircuits" in url and "actualTemp" in url:
            return _mock_json_response({"value": 45.0})
        if "dhwCircuits" in url and "chargeRemainingTime" in url:
            return _mock_json_response({"value": 10})
        if "dhwCircuits" in url and "singleChargeSetpoint" in url:
            return _mock_json_response({"value": 55})
        if "dhwCircuits" in url and "currentTemperatureLevel" in url:
            return _mock_json_response(
                {"value": "high", "allowedValues": ["off", "high", "low"]}
            )
        if "dhwCircuits" in url and "temperatureLevels" in url:
            level = url.split("/")[-1]
            return _mock_json_response({"value": 60 if level == "high" else 40})
        if (
            "dhwCircuits" in url
            and "charge" in url
            and "Duration" not in url
            and "Setpoint" not in url
            and "Remaining" not in url
        ):
            return _mock_json_response({"value": "off"})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response(
                {
                    "references": [{"id": "/dhwCircuits/dhw1"}],
                }
            )
        if "heatingCircuits" in url and "operationMode" in url:
            return _mock_json_response({"value": "auto"})
        if "heatingCircuits" in url and "currentSuWiMode" in url:
            return _mock_json_response({"value": "summer"})
        if "heatingCircuits" in url and "heatCoolMode" in url:
            return _mock_json_response({"value": "heat"})
        if "heatingCircuits" in url and "roomtemperature" in url:
            return _mock_json_response({"value": 21.5})
        if "heatingCircuits" in url and "actualHumidity" in url:
            return _mock_json_response({"value": 55})
        if "heatingCircuits" in url and "manualRoomSetpoint" in url:
            return _mock_json_response({"value": 20})
        if "heatingCircuits" in url and "currentRoomSetpoint" in url:
            return _mock_json_response({"value": 21})
        if "heatingCircuits" in url and "cooling/roomTempSetpoint" in url:
            return _mock_json_response({"value": 25})
        if url.endswith("/resource/heatingCircuits"):
            return _mock_json_response(
                {
                    "references": [{"id": "/heatingCircuits/hc1"}],
                }
            )
        if "heatPumpType" in url:
            return _mock_json_response({"value": "airToWater"})
        if "numberOfStarts" in url:
            return _mock_json_response({"value": 100})
        if "returnTemperature" in url:
            return _mock_json_response({"value": 30})
        if "actualSupplyTemperature" in url:
            return _mock_json_response({"value": 35})
        if "actualModulation" in url:
            return _mock_json_response({"value": 50})
        if "collectorInflowTemp" in url:
            return _mock_json_response({"value": 10})
        if "collectorOutflowTemp" in url:
            return _mock_json_response({"value": 8})
        if "actualHeatDemand" in url:
            return _mock_json_response({"value": 80})
        if "workingTime" in url:
            return _mock_json_response({"value": 5000})
        if "totalConsumption" in url:
            return _mock_json_response({"value": 1234})
        if "systemPressure" in url:
            return _mock_json_response({"value": 1.5})
        if "holidayMode" in url:
            return _mock_json_response({"value": "off"})
        if "awayMode" in url:
            return _mock_json_response({"value": "off"})
        if "powerLimitation" in url:
            return _mock_json_response({"value": "off"})
        if "outdoor_t1" in url:
            return _mock_json_response({"value": 5.0})
        if "ventilation" in url:
            return _mock_json_response({"references": []})
        if "bulk" in url:
            return _mock_json_response(
                [{"resourcePaths": [{"gatewayResponse": {"payload": {"value": 99}}}]}]
            )
        return _mock_json_response({})

    with patch.object(k40, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await k40.async_update(DEVICE_ID)

    assert result.device == DEVICE_ID
    assert isinstance(result.dhw_circuits, list)
    assert len(result.dhw_circuits) == 1
    # tempLevel should have 'high' and 'low' (not 'off')
    assert "high" in result.dhw_circuits[0]["tempLevel"]
    assert "low" in result.dhw_circuits[0]["tempLevel"]
    assert "off" not in result.dhw_circuits[0]["tempLevel"]
    assert isinstance(result.heating_circuits, list)
    assert len(result.heating_circuits) == 1

    await session.close()


@pytest.mark.asyncio
async def test_k40_async_update_empty_references() -> None:
    """K40 update when DHW, HC and ventilation have no references."""
    session = ClientSession()
    k40 = _make_k40(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001
        if "notifications" in url:
            return _mock_json_response({"values": []})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response({"references": []})
        if url.endswith("/resource/heatingCircuits"):
            return _mock_json_response({"references": []})
        if "ventilation" in url:
            return _mock_json_response({"references": []})
        if "bulk" in url:
            return _mock_json_response(
                [{"resourcePaths": [{"gatewayResponse": {"payload": {"value": 0}}}]}]
            )
        return _mock_json_response({})

    with patch.object(k40, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await k40.async_update(DEVICE_ID)

    assert result.dhw_circuits == {}
    assert result.heating_circuits == {}
    assert result.ventilation == {}

    await session.close()


@pytest.mark.asyncio
async def test_k40_async_update_with_ventilation() -> None:
    """K40 update with ventilation zones populated."""
    session = ClientSession()
    k40 = _make_k40(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001, PLR0911, PLR0912
        if "notifications" in url:
            return _mock_json_response({"values": []})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response({"references": []})
        if url.endswith("/resource/heatingCircuits"):
            return _mock_json_response({"references": []})
        if url.endswith("/resource/ventilation"):
            return _mock_json_response(
                {
                    "references": [{"id": "/ventilation/zone1"}],
                }
            )
        if "ventilation" in url and "exhaustFanLevel" in url:
            return _mock_json_response({"value": 3})
        if "ventilation" in url and "maxIndoorAirQuality" in url:
            return _mock_json_response({"value": 80})
        if "ventilation" in url and "maxRelativeHumidity" in url:
            return _mock_json_response({"value": 60})
        if "ventilation" in url and "operationMode" in url:
            return _mock_json_response({"value": "auto"})
        if "ventilation" in url and "exhaustTemp" in url:
            return _mock_json_response({"value": 22})
        if "ventilation" in url and "extractTemp" in url:
            return _mock_json_response({"value": 23})
        if "ventilation" in url and "internalAirQuality" in url:
            return _mock_json_response({"value": 90})
        if "ventilation" in url and "internalHumidity" in url:
            return _mock_json_response({"value": 50})
        if "ventilation" in url and "outdoorTemp" in url:
            return _mock_json_response({"value": 5})
        if "ventilation" in url and "supplyTemp" in url:
            return _mock_json_response({"value": 20})
        if "ventilation" in url and "summerBypass/enable" in url:
            return _mock_json_response({"value": "off"})
        if "ventilation" in url and "summerBypass/duration" in url:
            return _mock_json_response({"value": 120})
        if "ventilation" in url and "demand/indoorAirQuality" in url:
            return _mock_json_response({"value": 70})
        if "ventilation" in url and "demand/relativeHumidity" in url:
            return _mock_json_response({"value": 55})
        if "bulk" in url:
            return _mock_json_response(
                [{"resourcePaths": [{"gatewayResponse": {"payload": {"value": 0}}}]}]
            )
        return _mock_json_response({})

    with patch.object(k40, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await k40.async_update(DEVICE_ID)

    assert isinstance(result.ventilation, list)
    assert len(result.ventilation) == 1
    assert result.ventilation[0]["exhaustFanLevel"] == {"value": 3}

    await session.close()


# ---------------------------------------------------------------------------
# K40 individual methods
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_k40_dhw_operation_mode_get_put() -> None:
    """Test K40 DHW operation mode get and put."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "auto"})),
    ) as mock_req:
        result = await k40.async_get_dhw_operation_mode(DEVICE_ID, "dhw1")
        assert result == {"value": "auto"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_dhw_operation_mode(DEVICE_ID, "dhw1", "manual")
        assert mock_req.call_args[0][2] == {"value": "manual"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_hc_operation_mode_get_put() -> None:
    """Test K40 HC operation mode get and put."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "auto"})),
    ) as mock_req:
        result = await k40.async_get_hc_operation_mode(DEVICE_ID, "hc1")
        assert result == {"value": "auto"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_hc_operation_mode(DEVICE_ID, "hc1", "manual")
        assert mock_req.call_args[0][2] == {"value": "manual"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_hc_suwi_mode() -> None:
    """Test K40 HC summer/winter mode get and put."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "summer"})),
    ) as mock_req:
        result = await k40.async_get_hc_suwi_mode(DEVICE_ID, "hc1")
        assert result == {"value": "summer"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_hc_suwi_mode(DEVICE_ID, "hc1", "winter")
        assert mock_req.call_args[0][2] == {"value": "winter"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_hc_heatcool_mode() -> None:
    """Test K40 HC heat/cool mode get and put."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "heat"})),
    ) as mock_req:
        result = await k40.async_get_hc_heatcool_mode(DEVICE_ID, "hc1")
        assert result == {"value": "heat"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_hc_heatcool_mode(DEVICE_ID, "hc1", "cool")
        assert mock_req.call_args[0][2] == {"value": "cool"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_away_holiday_mode() -> None:
    """Test K40 away and holiday mode get and put."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "on"})),
    ):
        result = await k40.async_get_away_mode(DEVICE_ID)
        assert result == {"value": "on"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_away_mode(DEVICE_ID, "off")
        assert mock_req.call_args[0][2] == {"value": "off"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "off"})),
    ):
        result = await k40.async_get_holiday_mode(DEVICE_ID)
        assert result == {"value": "off"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_holiday_mode(DEVICE_ID, "on")
        assert mock_req.call_args[0][2] == {"value": "on"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_heat_source_getters() -> None:
    """Test K40 heat source getter methods."""
    session = ClientSession()
    k40 = _make_k40(session)

    for method_name in (
        "async_get_hs_type",
        "async_get_hs_pump_type",
        "async_get_hs_starts",
        "async_get_hs_return_temp",
        "async_get_hs_supply_temp",
        "async_get_hs_modulation",
        "async_get_hs_brine_inflow_temp",
        "async_get_hs_brine_outflow_temp",
        "async_get_hs_heat_demand",
        "async_get_hs_working_time",
        "async_get_hs_total_consumption",
        "async_get_hs_system_pressure",
        "async_get_power_limitation",
        "async_get_outdoor_temp",
    ):
        with patch.object(
            k40,
            "_async_http_request",
            new=AsyncMock(return_value=_mock_json_response({"value": 42})),
        ):
            result = await getattr(k40, method_name)(DEVICE_ID)
            assert result == {"value": 42}, f"{method_name} failed"

    await session.close()


@pytest.mark.asyncio
async def test_k40_hc_room_temp_and_setpoints() -> None:
    """Test K40 HC room temperature and setpoint methods."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 21.5})),
    ):
        assert await k40.async_get_hc_room_temp(DEVICE_ID, "hc1") == {"value": 21.5}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 55})),
    ):
        assert await k40.async_get_hc_actual_humidity(DEVICE_ID, "hc1") == {"value": 55}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 20})),
    ):
        assert await k40.async_get_hc_manual_room_setpoint(DEVICE_ID, "hc1") == {
            "value": 20
        }

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_hc_manual_room_setpoint(DEVICE_ID, "hc1", "22")
        assert mock_req.call_args[0][2] == {"value": "22"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 21})),
    ):
        assert await k40.async_get_hc_current_room_setpoint(DEVICE_ID, "hc1") == {
            "value": 21
        }

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 25})),
    ):
        assert await k40.async_get_hc_cooling_room_temp_setpoint(DEVICE_ID, "hc1") == {
            "value": 25
        }

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_hc_cooling_room_temp_setpoint(DEVICE_ID, "hc1", "24")
        assert mock_req.call_args[0][2] == {"value": "24"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "underfloor"})),
    ):
        assert await k40.async_get_hc_heating_type(DEVICE_ID, "hc1") == {
            "value": "underfloor"
        }

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "room"})),
    ):
        assert await k40.async_get_hc_control_type(DEVICE_ID, "hc1") == {
            "value": "room"
        }

    await session.close()


@pytest.mark.asyncio
async def test_k40_dhw_charge_methods() -> None:
    """Test K40 DHW charge-related methods."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "off"})),
    ):
        assert await k40.async_get_dhw_charge(DEVICE_ID, "dhw1") == {"value": "off"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_dhw_charge(DEVICE_ID, "dhw1", "on")
        assert mock_req.call_args[0][2] == {"value": "on"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 10})),
    ):
        assert await k40.async_get_dhw_charge_remaining_time(DEVICE_ID, "dhw1") == {
            "value": 10
        }

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 30})),
    ):
        assert await k40.async_get_dhw_charge_duration(DEVICE_ID, "dhw1") == {
            "value": 30
        }

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_dhw_charge_duration(DEVICE_ID, "dhw1", "45")
        assert mock_req.call_args[0][2] == {"value": "45"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 55})),
    ):
        assert await k40.async_get_dhw_charge_setpoint(DEVICE_ID, "dhw1") == {
            "value": 55
        }

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 45})),
    ):
        assert await k40.async_get_dhw_actual_temp(DEVICE_ID, "dhw1") == {"value": 45}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": "high"})),
    ):
        assert await k40.async_get_dhw_current_temp_level(DEVICE_ID, "dhw1") == {
            "value": "high"
        }

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_put_dhw_current_temp_level(DEVICE_ID, "dhw1", "low")
        assert mock_req.call_args[0][2] == {"value": "low"}

    with patch.object(
        k40,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 60})),
    ):
        assert await k40.async_get_dhw_temp_level(DEVICE_ID, "dhw1", "high") == {
            "value": 60
        }

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_dhw_temp_level(DEVICE_ID, "dhw1", "high", "65")
        assert mock_req.call_args[0][2] == {"value": "65"}

    await session.close()


@pytest.mark.asyncio
async def test_k40_get_consumption_payload_present() -> None:
    """Test consumption when payload key is present."""
    session = ClientSession()
    k40 = _make_k40(session)
    bulk_resp = _mock_json_response(
        [
            {
                "resourcePaths": [
                    {
                        "gatewayResponse": {
                            "payload": {"value": 123},
                        },
                    }
                ],
            }
        ]
    )

    with patch.object(
        k40, "_async_http_request", new=AsyncMock(return_value=bulk_resp)
    ):
        result = await k40.async_get_consumption(DEVICE_ID, "dhw", "2024-01-01")
        assert result == {"value": 123}

    await session.close()


@pytest.mark.asyncio
async def test_k40_get_consumption_no_payload() -> None:
    """Test consumption when payload key is absent (falls to except)."""
    session = ClientSession()
    k40 = _make_k40(session)
    bulk_resp = _mock_json_response(
        [
            {
                "resourcePaths": [
                    {
                        "gatewayResponse": {
                            "errorCode": 404,
                        },
                    }
                ],
            }
        ]
    )

    with patch.object(
        k40, "_async_http_request", new=AsyncMock(return_value=bulk_resp)
    ):
        result = await k40.async_get_consumption(DEVICE_ID, "total", "2024-01")
        assert result == {"errorCode": 404}

    await session.close()


@pytest.mark.asyncio
async def test_k40_ventilation_setters() -> None:
    """Test ventilation setter methods."""
    session = ClientSession()
    k40 = _make_k40(session)

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_ventilation_mode(DEVICE_ID, "zone1", "manual")
        assert mock_req.call_args[0][2] == {"value": "manual"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_ventilation_summer_enable(DEVICE_ID, "zone1", "on")
        assert mock_req.call_args[0][2] == {"value": "on"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_ventilation_summer_duration(DEVICE_ID, "zone1", "180")
        assert mock_req.call_args[0][2] == {"value": "180"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_ventilation_demand_quality(DEVICE_ID, "zone1", "high")
        assert mock_req.call_args[0][2] == {"value": "high"}

    with patch.object(k40, "_async_http_request", new=AsyncMock()) as mock_req:
        await k40.async_set_ventilation_demand_humidity(DEVICE_ID, "zone1", "60")
        assert mock_req.call_args[0][2] == {"value": "60"}

    await session.close()


# ===========================================================================
# HomeComWddw2
# ===========================================================================


def _make_wddw2(session):  # noqa: ANN001, ANN202
    return HomeComWddw2(session, _make_options(), DEVICE_ID, auth_provider=False)


@pytest.mark.asyncio
async def test_wddw2_async_update_with_dhw() -> None:
    """Full wddw2 update with dhw circuits and regex matching."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001, PLR0911
        if "notifications" in url:
            return _mock_json_response({"values": [{"code": "warn"}]})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response(
                {
                    "references": [{"id": "/dhwCircuits/dhw1"}],
                }
            )
        if "dhwCircuits" in url and "operationMode" in url:
            return _mock_json_response(
                {"value": "auto", "allowedValues": ["off", "manual", "auto"]}
            )
        if "dhwCircuits" in url and "airBoxTemperature" in url:
            return _mock_json_response({"value": 28})
        if "dhwCircuits" in url and "fanSpeed" in url:
            return _mock_json_response({"value": 1200})
        if "dhwCircuits" in url and "inletTemperature" in url:
            return _mock_json_response({"value": 15})
        if "dhwCircuits" in url and "outletTemperature" in url:
            return _mock_json_response({"value": 45})
        if "dhwCircuits" in url and "waterFlow" in url:
            return _mock_json_response({"value": 5.2})
        if "numberOfStarts" in url:
            return _mock_json_response({"value": 200})
        if "dhwCircuits" in url and "manualsetpoint" in url:
            return _mock_json_response({"value": 50})
        if "dhwCircuits" in url and "temperatureLevels" in url:
            return _mock_json_response({"value": 55})
        return _mock_json_response({})

    with patch.object(wddw2, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await wddw2.async_update(DEVICE_ID)

    assert result.device == DEVICE_ID
    assert result.notifications == [{"code": "warn"}]
    assert isinstance(result.dhw_circuits, list)
    assert len(result.dhw_circuits) == 1
    ref = result.dhw_circuits[0]
    assert ref["operationMode"]["value"] == "auto"
    assert ref["airBoxTemperature"] == {"value": 28}
    # tempLevel should have 'manual' and 'auto' (not 'off')
    assert "manual" in ref["tempLevel"]
    assert "auto" in ref["tempLevel"]
    assert "off" not in ref["tempLevel"]

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_async_update_non_matching_dhw_id() -> None:
    r"""DHW ID that doesn't match regex dhw\\d is skipped."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001
        if "notifications" in url:
            return _mock_json_response({"values": []})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response(
                {
                    "references": [{"id": "/dhwCircuits/dhw_extra_thing"}],
                }
            )
        return _mock_json_response({})

    with patch.object(wddw2, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await wddw2.async_update(DEVICE_ID)

    # The reference is still there but was not enriched
    assert isinstance(result.dhw_circuits, list)
    assert len(result.dhw_circuits) == 1
    assert "operationMode" not in result.dhw_circuits[0]

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_async_update_empty_references() -> None:
    """Empty references - references set to empty dict."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    async def route(method, url, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202, ARG001
        if "notifications" in url:
            return _mock_json_response({"values": []})
        if url.endswith("/resource/dhwCircuits"):
            return _mock_json_response({"references": []})
        return _mock_json_response({})

    with patch.object(wddw2, "_async_http_request", new=AsyncMock(side_effect=route)):
        result = await wddw2.async_update(DEVICE_ID)

    assert result.dhw_circuits == {}

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_dhw_temp_level_manual() -> None:
    """level='manual' uses the manual endpoint."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    with patch.object(
        wddw2,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 50})),
    ) as mock_req:
        result = await wddw2.async_get_dhw_temp_level(DEVICE_ID, "dhw1", "manual")
        assert result == {"value": 50}
        assert "manualsetpoint" in mock_req.call_args[0][1]

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_dhw_temp_level_other() -> None:
    """Level != 'manual' uses the normal temperatureLevels endpoint."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    with patch.object(
        wddw2,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 60})),
    ) as mock_req:
        result = await wddw2.async_get_dhw_temp_level(DEVICE_ID, "dhw1", "high")
        assert result == {"value": 60}
        assert "temperatureLevels/high" in mock_req.call_args[0][1]

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_set_dhw_temp_level() -> None:
    """Test WDDW2 set DHW temperature level rounds value."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    with patch.object(wddw2, "_async_http_request", new=AsyncMock()) as mock_req:
        await wddw2.async_set_dhw_temp_level(DEVICE_ID, "dhw1", "manual", 50.56)
        assert mock_req.call_args[0][2] == {"value": 50.6}

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_sensor_getters() -> None:
    """Test all wddw2 sensor getter methods."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    for method_name in (
        "async_get_dhw_airbox_temp",
        "async_get_dhw_fan_speed",
        "async_get_dhw_inlet_temp",
        "async_get_dhw_outlet_temp",
        "async_get_dhw_water_flow",
    ):
        with patch.object(
            wddw2,
            "_async_http_request",
            new=AsyncMock(return_value=_mock_json_response({"value": 42})),
        ):
            result = await getattr(wddw2, method_name)(DEVICE_ID, "dhw1")
            assert result == {"value": 42}, f"{method_name} failed"

    with patch.object(
        wddw2,
        "_async_http_request",
        new=AsyncMock(return_value=_mock_json_response({"value": 100})),
    ):
        result = await wddw2.async_get_hs_starts(DEVICE_ID)
        assert result == {"value": 100}

    await session.close()


@pytest.mark.asyncio
async def test_wddw2_dhw_operation_mode_put() -> None:
    """Test WDDW2 DHW operation mode put."""
    session = ClientSession()
    wddw2 = _make_wddw2(session)

    with patch.object(wddw2, "_async_http_request", new=AsyncMock()) as mock_req:
        await wddw2.async_put_dhw_operation_mode(DEVICE_ID, "dhw1", "manual")
        assert mock_req.call_args[0][2] == {"value": "manual"}

    await session.close()


# ===========================================================================
# Brand selection (Bosch / Buderus)
# ===========================================================================


@pytest.mark.asyncio
async def test_brand_default_is_bosch() -> None:
    """Default brand selects Bosch OAuth params."""
    session = ClientSession()
    options = _make_options()
    bhc = HomeComAlt(session, options, auth_provider=True)
    assert bhc._oauth_params is OAUTH_PARAMS
    await session.close()


@pytest.mark.asyncio
async def test_brand_buderus_selects_buderus_oauth_params() -> None:
    """brand='buderus' selects Buderus OAuth params."""
    session = ClientSession()
    options = _make_options(brand="buderus")
    bhc = HomeComAlt(session, options, auth_provider=True)
    assert bhc._oauth_params is OAUTH_PARAMS_BUDERUS
    await session.close()


@pytest.mark.asyncio
async def test_validate_auth_uses_buderus_params() -> None:
    """validate_auth encodes Buderus redirect_uri when brand='buderus'."""
    session = ClientSession()
    options = ConnectionOptions(code="test_code", brand="buderus")
    homecom = HomeComAlt(session, options, auth_provider=True)

    with patch.object(homecom, "_async_http_request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value={
                "access_token": "test_token",
                "refresh_token": "refresh_token",
            }
        )
        mock_request.return_value = mock_response

        await homecom.validate_auth("auth_code", "code_verifier")
        call_data = mock_request.call_args[0][2]
        assert "com.buderus.tt.dashtt" in call_data
        assert "com.bosch.tt.dashtt" not in call_data

    await session.close()


@pytest.mark.asyncio
async def test_get_token_refresh_uses_instance_params() -> None:
    """get_token refresh path uses instance _oauth_refresh_params."""
    session = ClientSession()
    options = _make_options(brand="buderus")
    bhc = HomeComAlt(session, options, auth_provider=True)

    mock_resp = _mock_json_response(
        {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
        }
    )

    with (
        patch.object(bhc, "check_jwt", return_value=False),
        patch.object(bhc, "_async_http_request", new=AsyncMock(return_value=mock_resp)),
    ):
        result = await bhc.get_token()
        assert result is True
        assert bhc.token == "new_access"
        assert bhc.refresh_token == "new_refresh"

    await session.close()


@pytest.mark.asyncio
async def test_connection_options_brand_default() -> None:
    """ConnectionOptions defaults brand to 'bosch'."""
    opts = ConnectionOptions()
    assert opts.brand == "bosch"
