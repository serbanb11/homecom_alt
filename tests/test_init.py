"""Tests for init homecom_alt."""

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

import jwt
import pytest
from aiohttp import ClientConnectorError, ClientResponseError, ClientSession
from aioresponses import aioresponses

from homecom_alt import (
    ApiError,
    AuthFailedError,
    ConnectionOptions,
    HomeComAlt,
    NotRespondingError,
)
from homecom_alt.const import (
    OAUTH_DOMAIN,
    OAUTH_ENDPOINT,
    OAUTH_PARAMS,
)


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
    """Test aiohttp json request."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with (
        aioresponses() as session_mock,
        patch("homecom_alt.HomeComAlt._async_http_request") as mock_request,
    ):
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.OK
        mock_response.json = AsyncMock(return_value={"key": "value"})
        session_mock.return_value = mock_response

        await bhc._async_http_request("get", "http://test.com", type=1)

    await session.close()

    assert mock_request.call_count == 1
    assert mock_request.call_args[0][0] == "get"
    assert mock_request.call_args[0][1] == "http://test.com"


@pytest.mark.asyncio
async def test_async_http_request_success_form() -> None:
    """Test aiohttp request."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with (
        aioresponses() as session_mock,
        patch("homecom_alt.HomeComAlt._async_http_request") as mock_request,
    ):
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.OK
        mock_response.json = AsyncMock(return_value={"key": "value"})
        session_mock.return_value = mock_response

        await bhc._async_http_request("get", "http://test.com", type=2)

    await session.close()

    assert mock_request.call_count == 1
    assert mock_request.call_args[0][0] == "get"
    assert mock_request.call_args[0][1] == "http://test.com"


@pytest.mark.asyncio
async def test_async_http_request_unauthorized() -> None:
    """Test unauthorized aiohttp request."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        session = ClientSession()
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.UNAUTHORIZED
        )

        with pytest.raises(AuthFailedError):
            await bhc._async_http_request("get", "http://test.com")


@pytest.mark.asyncio
async def test_async_http_request_bad_request() -> None:
    """Test invalid refresh token."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        session = ClientSession()
        mock_request.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.BAD_REQUEST
        )

        response = await bhc._async_http_request(
            "post", "https://singlekey-id.com/auth/connect/token"
        )
        assert response is None


@pytest.mark.asyncio
async def test_async_http_request_timeout() -> None:
    """Test aiohttp request timeout."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        session = ClientSession()
        mock_request.side_effect = ClientConnectorError(None, OSError())

        with pytest.raises(NotRespondingError):
            await bhc._async_http_request("get", "http://test.com")


@pytest.mark.asyncio
async def test_async_http_request_invalid_status() -> None:
    """Test aiohttp response with invalid status."""
    session = ClientSession()
    options = ConnectionOptions(
        username="test_user",
        password="test_pass",
        token=create_test_jwt(),
        refresh_token="test_refresh",
    )

    bhc = await HomeComAlt.create(session, options)
    with patch.object(ClientSession, "request", new=AsyncMock()) as mock_request:
        session = ClientSession()
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.INTERNAL_SERVER_ERROR
        mock_request.return_value = mock_response

        with pytest.raises(ApiError):
            await bhc._async_http_request("get", "http://test.com")


@pytest.mark.asyncio
async def test_check_jwt_valid() -> None:
    """Test jwt validity function."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        password="test_pass",
    )
    homecom_alt: HomeComAlt = await HomeComAlt.create(session, options)
    assert homecom_alt.check_jwt() is True


@pytest.mark.asyncio
async def test_check_jwt_invalid() -> None:
    """Test invalid jwt."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        password="test_pass",
    )
    homecom_alt: HomeComAlt = await HomeComAlt.create(session, options)
    homecom_alt._options.token = create_test_jwt(
        expiration=int((datetime.now(UTC) - timedelta(days=1)).timestamp())
    )
    assert homecom_alt.check_jwt() is False


@pytest.mark.asyncio
async def test_get_token_valid_jwt() -> None:
    """Test valid jwt."""
    session = ClientSession()
    options = ConnectionOptions(
        token=create_test_jwt(),
        refresh_token="test_refresh_token",
        username="test_user",
        password="test_pass",
    )
    homecom_alt: HomeComAlt = await HomeComAlt.create(session, options)
    with patch.object(homecom_alt, "check_jwt", return_value=True):
        assert await homecom_alt.get_token() is None


@pytest.mark.asyncio
async def test_do_auth_step3_success() -> None:
    """Test successful password submission in do_auth_step3."""
    session = ClientSession()
    homecom = HomeComAlt(session, ConnectionOptions(password="test_pass"))

    with patch.object(session, "post", new=AsyncMock()) as mock_post:
        mock_response = AsyncMock()
        mock_response.status = HTTPStatus.OK
        mock_post.return_value = mock_response

        response = await homecom.do_auth_step3("https://auth.com", "csrf_token")
        assert response == mock_response
        mock_post.assert_called_once_with(
            "https://auth.com",
            data={"Password": "test_pass", "__RequestVerificationToken": "csrf_token"},
            allow_redirects=False,
        )

    await session.close()


@pytest.mark.asyncio
async def test_do_auth_step3_unauthorized() -> None:
    """Test do_auth_step3 raising AuthFailedError on 401."""
    session = ClientSession()
    homecom = HomeComAlt(session, ConnectionOptions(password="test_pass"))

    with patch.object(session, "post", new=AsyncMock()) as mock_post:
        mock_post.side_effect = ClientResponseError(
            None, (), status=HTTPStatus.UNAUTHORIZED
        )

        with pytest.raises(AuthFailedError, match="Authorization has failed"):
            await homecom.do_auth_step3("https://auth.com", "csrf_token")

    await session.close()


@pytest.mark.asyncio
async def test_do_auth_step_failure() -> None:
    """Test do_auth failing when a step fails."""
    session = ClientSession()
    homecom = HomeComAlt(session, ConnectionOptions())

    with (
        patch.object(
            homecom,
            "do_auth_step1",
            new=AsyncMock(side_effect=AuthFailedError("Step 1 failed")),
        ),
        pytest.raises(AuthFailedError, match="Step 1 failed"),
    ):
        await homecom.do_auth()

    await session.close()


@pytest.mark.asyncio
async def test_validate_auth_success() -> None:
    """Test validate_auth exchanging an auth code for a token."""
    session = ClientSession()
    homecom = HomeComAlt(session, ConnectionOptions())

    with patch.object(homecom, "_async_http_request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"access_token": "test_token"})
        mock_request.return_value = mock_response

        token = await homecom.validate_auth("auth_code", "code_verifier")
        assert token == {"access_token": "test_token"}

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
    """Test validate_auth raising AuthFailedError on invalid response."""
    session = ClientSession()
    homecom = HomeComAlt(session, ConnectionOptions())

    with patch.object(homecom, "_async_http_request", new=AsyncMock()) as mock_request:
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(side_effect=ValueError("Invalid JSON"))
        mock_request.return_value = mock_response

        with pytest.raises(AuthFailedError, match="Authorization has failed"):
            await homecom.validate_auth("auth_code", "code_verifier")

    await session.close()
