"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import jwt
from aiohttp import (
    ClientConnectorError,
    ClientResponseError,
    ClientSession,
    ContentTypeError,
)
from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_incrementing,
)

from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_BULK,
    BOSCHCOM_ENDPOINT_DWH_WATER_TOTAL_CONSUMPTION,
    BOSCHCOM_ENDPOINT_FIRMWARE,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HS_ACTUAL_POWER,
    BOSCHCOM_ENDPOINT_HS_ELECTRICITY_TOTAL_CONSUMPTION,
    BOSCHCOM_ENDPOINT_HS_OPERATION_HOURS,
    BOSCHCOM_ENDPOINT_HS_POWER_PERCENTAGE,
    BOSCHCOM_ENDPOINT_HS_TOTAL_NUMBER_OF_STARTS,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_PV_LIST,
    BOSCHCOM_ENDPOINT_SYSTEM_BRAND,
    BOSCHCOM_ENDPOINT_SYSTEM_HEALTH_STATUS,
    BOSCHCOM_ENDPOINT_SYSTEM_INFO,
    BOSCHCOM_ENDPOINT_TIME,
    BOSCHCOM_ENDPOINT_TIME2,
    DEFAULT_TIMEOUT,
    JSON,
    MAX_BULK_ENDPOINTS,
    OAUTH_BROWSER_VERIFIER,
    OAUTH_DOMAIN,
    OAUTH_ENDPOINT,
    OAUTH_PARAMS,
    OAUTH_PARAMS_BUDERUS,
    OAUTH_REFRESH_PARAMS,
    URLENCODED,
)
from .exceptions import (
    ApiError,
    AuthFailedError,
    InvalidSensorDataError,
    NotRespondingError,
)

if TYPE_CHECKING:
    from .model import (
        ConnectionOptions,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours

# Per-endpoint statuses that are expected for unsupported/forbidden resources.
# These are logged at debug level to avoid spamming the log (see issue #143).
_EXPECTED_ENDPOINT_STATUSES: frozenset[int] = frozenset(
    {HTTPStatus.FORBIDDEN.value, HTTPStatus.NOT_FOUND.value}
)


class HomeComAlt:
    """Main class to perform HomeCom Easy requests."""

    def __init__(
        self, session: ClientSession, options: ConnectionOptions, auth_provider: bool
    ) -> None:
        """Initialize."""
        self._options = options
        self._session = session
        self._count = 0
        self._update_errors: int = 0
        self._auth_provider = auth_provider
        self._oauth_params = (
            OAUTH_PARAMS_BUDERUS if options.brand == "buderus" else OAUTH_PARAMS
        )
        self._oauth_refresh_params = OAUTH_REFRESH_PARAMS
        self._lock = asyncio.Lock()
        self._not_found_cache: dict[str, float] = {}

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token."""
        return self._options.refresh_token

    @refresh_token.setter
    def refresh_token(self, value: str) -> None:
        """Set the refresh token."""
        self._options.refresh_token = value

    @property
    def token(self) -> str | None:
        """Return the access token."""
        return self._options.token

    @token.setter
    def token(self, value: str) -> None:
        """Set the access token."""
        self._options.token = value

    @classmethod
    async def create(
        cls, session: ClientSession, options: ConnectionOptions, auth_provider: bool
    ) -> HomeComAlt:
        """Create a new device instance."""
        return cls(session, options, auth_provider)

    async def async_request_bulk(
        self, device_id: str, endpoints: list[str]
    ) -> dict[str, Any] | None:
        """Retrieve data from the device with an endpoint bundling multiple requests.

        Automatically chunks into multiple calls if more than
        MAX_BULK_ENDPOINTS are requested (API limit).
        """
        await self.get_token()

        if len(endpoints) <= MAX_BULK_ENDPOINTS:
            return await self._async_request_bulk_single(device_id, endpoints)

        # Chunk into multiple bulk calls
        result: dict[str, Any] = {}
        for i in range(0, len(endpoints), MAX_BULK_ENDPOINTS):
            chunk = endpoints[i : i + MAX_BULK_ENDPOINTS]
            chunk_result = await self._async_request_bulk_single(device_id, chunk)
            if chunk_result:
                result.update(chunk_result)
        return result or None

    async def _async_request_bulk_single(
        self, device_id: str, endpoints: list[str]
    ) -> dict[str, Any] | None:
        """Send a single bulk request for up to 30 endpoints."""
        # The bulk endpoint expects resource paths WITHOUT the "/resource"
        # prefix; sending the full path returns serverStatus 403 with a null
        # gatewayResponse. Strip on send and map back to original keys when
        # parsing the response.
        sent_to_original: dict[str, str] = {
            e.removeprefix("/resource"): e for e in endpoints
        }
        response = await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN + BOSCHCOM_ENDPOINT_BULK,
            [
                {
                    "gatewayId": device_id,
                    "resourcePaths": list(sent_to_original.keys()),
                }
            ],
            JSON,
        )
        json_response = await self._to_data(response)
        if json_response is None:
            return None

        result: dict[str, Any] = {}
        try:
            device_response = json_response[0]
            endpoint_responses = device_response["resourcePaths"]
            for endpoint_response in endpoint_responses:
                returned_path = endpoint_response["resourcePath"]
                endpoint = sent_to_original.get(returned_path, returned_path)
                server_status = endpoint_response["serverStatus"]
                if server_status != HTTPStatus.OK.value:
                    self._log_endpoint_status(endpoint, server_status)
                    continue
                device_endpoint_response = endpoint_response["gatewayResponse"]
                device_endpoint_response_status = device_endpoint_response["status"]
                if device_endpoint_response_status != HTTPStatus.OK.value:
                    self._log_endpoint_status(endpoint, device_endpoint_response_status)
                    continue
                payload = device_endpoint_response["payload"]
                result[endpoint] = payload
        except (KeyError, IndexError, TypeError):
            return None
        else:
            return result

    @staticmethod
    def _log_endpoint_status(endpoint: str, status: int) -> None:
        """Log a non-OK per-endpoint bulk status.

        Expected statuses (403/404) for unsupported or forbidden resources are
        logged at debug level to avoid spamming the log; anything else is a
        warning. See issue #143.
        """
        if status in _EXPECTED_ENDPOINT_STATUSES:
            _LOGGER.debug("Endpoint %s returned %s", endpoint, status)
        else:
            _LOGGER.warning("Endpoint %s returned %s", endpoint, status)

    async def _async_http_request(  # noqa: PLR0912
        self,
        method: str,
        url: str,
        data: Any | None = None,
        req_type: int | None = None,
    ) -> Any:
        """Retrieve data from the device."""
        if method.upper() == "GET" and url in self._not_found_cache:
            if time.monotonic() - self._not_found_cache[url] < _NOT_FOUND_CACHE_TTL:
                _LOGGER.debug("Skipping cached 404 endpoint %s", url)
                return {}
            del self._not_found_cache[url]

        headers = {
            "Authorization": f"Bearer {self._options.token}",  # Set Bearer token
            "Accept-Encoding": "gzip, deflate, br",
        }
        # JSON request
        if req_type == JSON:
            headers["Content-Type"] = "application/json; charset=UTF-8"
        elif req_type == URLENCODED:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            _LOGGER.debug("Requesting %s, method: %s", url, method)
            resp = await self._session.request(
                method,
                url,
                raise_for_status=True,
                data=data if req_type != JSON else None,
                json=data if req_type == JSON else None,
                timeout=DEFAULT_TIMEOUT,
                headers=headers,
                skip_auto_headers=["Accept"],
                allow_redirects=True,
            )
        except ClientResponseError as error:
            if error.status == HTTPStatus.UNAUTHORIZED.value:
                raise AuthFailedError("Authorization has failed") from error
            if (
                error.status == HTTPStatus.BAD_REQUEST.value
                and url == "https://singlekey-id.com/auth/connect/token"
            ):
                return None
            if error.status == HTTPStatus.NOT_FOUND.value:
                _LOGGER.debug("Endpoint %s returned %s", url, error.status)
                if method.upper() == "GET":
                    self._not_found_cache[url] = time.monotonic()
                return {}
            if error.status == HTTPStatus.FORBIDDEN.value:
                _LOGGER.debug("Endpoint %s returned %s", url, error.status)
                return {}
            if error.status in (
                HTTPStatus.BAD_GATEWAY.value,  # 502
                HTTPStatus.GATEWAY_TIMEOUT.value,  # 504
            ):
                _LOGGER.warning("Endpoint %s returned %s", url, error.status)
                return {}
            if error.status == HTTPStatus.TOO_MANY_REQUESTS.value:
                _LOGGER.warning("Endpoint %s returned %s", url, error.status)
                raise NotRespondingError(f"{url} is rate limited") from error
            raise ApiError(
                f"Invalid response from url {url}: {error.status}"
            ) from error
        except (TimeoutError, ClientConnectorError) as error:
            raise NotRespondingError(f"{url} is not responding") from error

        _LOGGER.debug("Data retrieved from %s, status: %s", url, resp.status)
        if resp.status not in {HTTPStatus.OK.value, HTTPStatus.NO_CONTENT.value}:
            raise ApiError(f"Invalid response from {url}: {resp.status}")

        return resp

    @staticmethod
    async def _to_data(response: Any) -> Any | None:
        if not response:
            return None
        try:
            return await response.json()
        except (ValueError, ContentTypeError) as error:
            _LOGGER.warning("Failed to parse response as JSON: %s", error)
            return None

    @retry(
        retry=retry_if_exception_type(NotRespondingError),
        stop=stop_after_attempt(5),
        wait=wait_incrementing(start=5, increment=5),
        after=after_log(_LOGGER, logging.DEBUG),
    )
    async def async_get_devices(self) -> Any:
        """Get devices."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN + BOSCHCOM_ENDPOINT_GATEWAYS,
        )
        try:
            return response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_firmware(self, device_id: str) -> Any:
        """Get firmware."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_FIRMWARE,
        )
        return await self._to_data(response)

    async def async_get_system_info(self, device_id: str) -> Any:
        """Get system info."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_INFO,
        )
        return await self._to_data(response)

    async def async_get_system_health_status(self, device_id: str) -> Any:
        """Get system health status (ok/error/maintenance)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_HEALTH_STATUS,
        )
        return await self._to_data(response)

    async def async_get_system_brand(self, device_id: str) -> Any:
        """Get system brand identifier."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_BRAND,
        )
        return await self._to_data(response)

    async def async_get_hs_total_number_of_starts(self, device_id: str) -> Any:
        """Get total heat-source number of starts (top-level, not hs1)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_TOTAL_NUMBER_OF_STARTS,
        )
        return await self._to_data(response)

    async def async_get_hs_actual_power(self, device_id: str) -> Any:
        """Get current heat-source power draw (hs1/actualPower)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_ACTUAL_POWER,
        )
        return await self._to_data(response)

    async def async_get_hs_power_percentage(self, device_id: str) -> Any:
        """Get heat-source power percentage (hs1/powerPercentage)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_POWER_PERCENTAGE,
        )
        return await self._to_data(response)

    async def async_get_hs_operation_hours(self, device_id: str) -> Any:
        """Get cumulative heat-source operating hours (hs1/operationHours)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_OPERATION_HOURS,
        )
        return await self._to_data(response)

    async def async_get_hs_electricity_total_consumption(self, device_id: str) -> Any:
        """Get total electricity consumed by heat sources (kWh)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_ELECTRICITY_TOTAL_CONSUMPTION,
        )
        return await self._to_data(response)

    async def async_get_dhw_water_total_consumption(self, device_id: str) -> Any:
        """Get total DHW water consumption (litres, top-level dhwCircuits)."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DWH_WATER_TOTAL_CONSUMPTION,
        )
        return await self._to_data(response)

    async def async_get_notifications(self, device_id: str) -> Any:
        """Get notifications."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_NOTIFICATIONS,
        )
        return await self._to_data(response)

    async def async_get_pv_list(self, device_id: str) -> Any:
        """Get pv list."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_PV_LIST,
        )
        return await self._to_data(response)

    async def async_get_time(self, device_id: str) -> Any:
        """Get gateway time."""
        last_exc: Exception | None = None

        for ep in (BOSCHCOM_ENDPOINT_TIME, BOSCHCOM_ENDPOINT_TIME2):
            try:
                response = await self._async_http_request(
                    "get",
                    BOSCHCOM_DOMAIN + BOSCHCOM_ENDPOINT_GATEWAYS + device_id + ep,
                )
                if isinstance(response, dict) and response == {}:
                    raise ApiError(f"{ep} not supported for this device.")  # noqa: TRY301
                return await self._to_data(response)
            except AuthFailedError:
                raise
            except (ApiError, NotRespondingError) as exc:
                last_exc = exc
                continue
        raise last_exc or ApiError("Both time endpoints failed.")

    def check_jwt(self) -> bool:
        """Check if token is expired."""
        if not self._options.token:
            return False
        try:
            exp = jwt.decode(
                self._options.token, options={"verify_signature": False}
            ).get("exp")
            if exp is None:
                _LOGGER.error("Token missing 'exp' claim")
                return False
            return datetime.now(UTC) < datetime.fromtimestamp(exp, UTC) - timedelta(
                minutes=5
            )
        except jwt.DecodeError as err:
            _LOGGER.error("Invalid token: %s", err)
            return False

    async def get_token(self) -> bool | None:
        """Retrieve a new token using the refresh token."""
        if self._auth_provider:
            if self.check_jwt():
                return None

            async with self._lock:
                if self.check_jwt():
                    return None

                if self._options.refresh_token:
                    data = {**self._oauth_refresh_params}
                    data["refresh_token"] = self._options.refresh_token
                    response = await self._async_http_request(
                        "post", OAUTH_DOMAIN + OAUTH_ENDPOINT, data, 2
                    )
                    if response is not None:
                        try:
                            response_json = await response.json()
                        except ValueError as error:
                            raise InvalidSensorDataError(
                                "Invalid devices data"
                            ) from error

                        if response_json:
                            self._options.token = response_json["access_token"]
                            self._options.refresh_token = response_json["refresh_token"]
                            return True

                if self._options.code:
                    response = await self.validate_auth(
                        self._options.code, OAUTH_BROWSER_VERIFIER
                    )
                    if response:
                        self._options.code = None
                        self._options.token = response["access_token"]
                        self._options.refresh_token = response["refresh_token"]
                        return True
                raise AuthFailedError("Failed to refresh")
        return None

    async def validate_auth(self, code: str, code_verifier: str) -> Any | None:
        """Get access and refresh token from singlekey-id."""
        response = await self._async_http_request(
            "post",
            OAUTH_DOMAIN + OAUTH_ENDPOINT,
            "code="
            + code
            + "&"
            + urlencode(self._oauth_params)
            + "&code_verifier="
            + code_verifier,
            2,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise AuthFailedError("Authorization has failed") from error

    async def async_action_universal_get(self, device_id: str, path: str) -> Any:
        """Query any endpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN + BOSCHCOM_ENDPOINT_GATEWAYS + device_id + path,
        )
        return await self._to_data(response)
