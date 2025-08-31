"""Tests for HomeComAlt module."""
# pylint: disable=protected-access

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

import jwt
import pytest
from aiohttp import ClientConnectorError, ClientResponseError, ClientSession

from homecom_alt import (
    ApiError,
    AuthFailedError,
    ConnectionOptions,
    HomeComAlt,
    NotRespondingError,
)
from homecom_alt.const import OAUTH_DOMAIN, OAUTH_ENDPOINT, OAUTH_PARAMS


def create_test_jwt(expiration: int = 9999999999) -> str:
    """Create a valid JWT token for testing."""
    secret = "test_secret_key"
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "exp": expiration,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.mark.asyncio
async def test_async_http_request_success_json() -> None:
    """Test that _async_http_request returns a successful response for JSON requests."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.OK
        mock_response.json = AsyncMock(return_value={"key": "value"})
        mock_request.return_value = mock_response

        resp = await bhc._async_http_request("get", "http://test.com", req_type=1)
        assert resp.status == HTTPStatus.OK

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_success_form() -> None:
    """Test that _async_http_request returns a successful response for form requests."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.OK
        mock_response.json = AsyncMock(return_value={"key": "value"})
        mock_request.return_value = mock_response

        resp = await bhc._async_http_request("get", "http://test.com", req_type=2)
        assert resp.status == HTTPStatus.OK

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_unauthorized() -> None:
    """Test that _async_http_request raises AuthFailedError on 401 response."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
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
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
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
async def test_async_http_request_timeout() -> None:
    """Test that _async_http_request raises NotRespondingError on connection timeout."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_request.side_effect = ClientConnectorError(None, OSError())
        with pytest.raises(NotRespondingError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_async_http_request_invalid_status() -> None:
    """Test that ApiError for HTTP errors other than 200/204."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        token=create_test_jwt(),
        refresh_token="test_refresh",
        code="test_code",
    )
    bhc = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.INTERNAL_SERVER_ERROR
        mock_request.return_value = mock_response
        with pytest.raises(ApiError):
            await bhc._async_http_request("get", "http://test.com")

    await session.close()


@pytest.mark.asyncio
async def test_check_jwt_valid() -> None:
    """Test that check_jwt returns True for a valid, unexpired token."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        code="test_code",
    )
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)
    assert homecom_alt.check_jwt() is True
    await session.close()


@pytest.mark.asyncio
async def test_check_jwt_invalid() -> None:
    """Test that check_jwt returns False for an expired token."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        code="test_code",
    )
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)
    homecom_alt._options.token = create_test_jwt(
        expiration=int((datetime.now(UTC) - timedelta(days=1)).timestamp())
    )
    assert homecom_alt.check_jwt() is False
    await session.close()


@pytest.mark.asyncio
async def test_get_token_valid_jwt() -> None:
    """Test that get_token returns None if the JWT is still valid."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        code="test_code",
    )
    homecom_alt = await HomeComAlt.create(session, options, auth_provider=True)

    with patch.object(homecom_alt, "check_jwt", return_value=True):
        assert await homecom_alt.get_token() is None

    await session.close()


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
