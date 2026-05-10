"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any, Literal
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
    BOSCHCOM_ENDPOINT_ADVANCED,
    BOSCHCOM_ENDPOINT_AIRFLOW_HORIZONTAL,
    BOSCHCOM_ENDPOINT_AIRFLOW_VERTICAL,
    BOSCHCOM_ENDPOINT_AWAY_MODE,
    BOSCHCOM_ENDPOINT_BULK,
    BOSCHCOM_ENDPOINT_CHILD_LOCK,
    BOSCHCOM_ENDPOINT_CONTROL,
    BOSCHCOM_ENDPOINT_CP,
    BOSCHCOM_ENDPOINT_CP_CHARGELOG,
    BOSCHCOM_ENDPOINT_CP_CMD_AUTHENTICATE,
    BOSCHCOM_ENDPOINT_CP_CMD_LIMIT,
    BOSCHCOM_ENDPOINT_CP_CMD_PAUSE,
    BOSCHCOM_ENDPOINT_CP_CMD_START,
    BOSCHCOM_ENDPOINT_CP_CONF,
    BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
    BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
    BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
    BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
    BOSCHCOM_ENDPOINT_CP_INFO,
    BOSCHCOM_ENDPOINT_CP_TELEMETRY,
    BOSCHCOM_ENDPOINT_DEVICE_ASSIGNED_HC,
    BOSCHCOM_ENDPOINT_DEVICE_BATTERY,
    BOSCHCOM_ENDPOINT_DEVICE_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_DEVICE_HUMIDITY,
    BOSCHCOM_ENDPOINT_DEVICE_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DEVICE_RF_STATUS,
    BOSCHCOM_ENDPOINT_DEVICE_ROOM_TEMP,
    BOSCHCOM_ENDPOINT_DEVICE_SGTIN,
    BOSCHCOM_ENDPOINT_DEVICE_SIGNAL,
    BOSCHCOM_ENDPOINT_DEVICE_TYPE,
    BOSCHCOM_ENDPOINT_DEVICE_ZONE_ID,
    BOSCHCOM_ENDPOINT_DEVICES,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DHW_HOLIDAY_ACTIVATED,
    BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_DWH_AIRBOX,
    BOSCHCOM_ENDPOINT_DWH_CHARGE,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
    BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_FAN_SPEED,
    BOSCHCOM_ENDPOINT_DWH_INLET_TEMP,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_OUTLET_TEMP,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_MANUAL,
    BOSCHCOM_ENDPOINT_DWH_WATER_FLOW,
    BOSCHCOM_ENDPOINT_ECO,
    BOSCHCOM_ENDPOINT_ENERGY_GAS_UNIT,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY_ENTRIES,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY_HOURLY,
    BOSCHCOM_ENDPOINT_ETH0_STATE,
    BOSCHCOM_ENDPOINT_FAN_SPEED,
    BOSCHCOM_ENDPOINT_FIRMWARE,
    BOSCHCOM_ENDPOINT_FULL_POWER,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY,
    BOSCHCOM_ENDPOINT_HC_CONTROL,
    BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
    BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
    BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
    BOSCHCOM_ENDPOINT_HC_HEATING_TYPE,
    BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED,
    BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
    BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
    BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
    BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
    BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
    BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
    BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
    BOSCHCOM_ENDPOINT_HC_SUWI_SWITCH_MODE,
    BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_A,
    BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_B,
    BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_MODE,
    BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_COMFORT2,
    BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_ECO,
    BOSCHCOM_ENDPOINT_HC_TEMPERATURE_LEVELS,
    BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
    BOSCHCOM_ENDPOINT_HM_DHW_MODE,
    BOSCHCOM_ENDPOINT_HM_FIX_TEMP,
    BOSCHCOM_ENDPOINT_HM_HC_MODE,
    BOSCHCOM_ENDPOINT_HM_START_STOP,
    BOSCHCOM_ENDPOINT_HOLIDAY_MODE,
    BOSCHCOM_ENDPOINT_HS_FLAME,
    BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND,
    BOSCHCOM_ENDPOINT_HS_INFLOW_TEMP,
    BOSCHCOM_ENDPOINT_HS_MODULATION,
    BOSCHCOM_ENDPOINT_HS_OUTFLOW_TEMP,
    BOSCHCOM_ENDPOINT_HS_PUMP_TYPE,
    BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
    BOSCHCOM_ENDPOINT_HS_STARTS,
    BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE,
    BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
    BOSCHCOM_ENDPOINT_HS_TYPE,
    BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
    BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY,
    BOSCHCOM_ENDPOINT_MODE,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
    BOSCHCOM_ENDPOINT_PLASMACLUSTER,
    BOSCHCOM_ENDPOINT_POWER_LIMITATION,
    BOSCHCOM_ENDPOINT_PV_LIST,
    BOSCHCOM_ENDPOINT_RRC2_DHW,
    BOSCHCOM_ENDPOINT_RRC2_DHW_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_RRC2_DHW_HOT_WATER_SYSTEM,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID,
    BOSCHCOM_ENDPOINT_RRC2_HC,
    BOSCHCOM_ENDPOINT_RRC2_HC_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_RRC2_HC_CONTROL_KEY,
    BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION,
    BOSCHCOM_ENDPOINT_RRC2_ZONE_ICON,
    BOSCHCOM_ENDPOINT_RRC2_ZONE_NAME,
    BOSCHCOM_ENDPOINT_RRC2_ZONE_TEMP_ACTUAL,
    BOSCHCOM_ENDPOINT_RRC2_ZONE_TEMP_HEATING_SETPOINT,
    BOSCHCOM_ENDPOINT_RRC2_ZONES,
    BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS,
    BOSCHCOM_ENDPOINT_STANDARD,
    BOSCHCOM_ENDPOINT_SWITCH,
    BOSCHCOM_ENDPOINT_SWITCH_ENABLE,
    BOSCHCOM_ENDPOINT_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_SYSTEM_BUS,
    BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES,
    BOSCHCOM_ENDPOINT_SYSTEM_INFO,
    BOSCHCOM_ENDPOINT_TEMP,
    BOSCHCOM_ENDPOINT_TIME,
    BOSCHCOM_ENDPOINT_TIME2,
    BOSCHCOM_ENDPOINT_TIMER,
    BOSCHCOM_ENDPOINT_VENTILATION,
    BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY,
    BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY,
    BOSCHCOM_ENDPOINT_VENTILATION_EXHAUST_TEMP,
    BOSCHCOM_ENDPOINT_VENTILATION_EXTRACT_TEMP,
    BOSCHCOM_ENDPOINT_VENTILATION_FAN,
    BOSCHCOM_ENDPOINT_VENTILATION_HUMIDITY,
    BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_HUMIDITY,
    BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_QUALITY,
    BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_VENTILATION_OUTDOOR_TEMP,
    BOSCHCOM_ENDPOINT_VENTILATION_QUALITY,
    BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION,
    BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE,
    BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_FLAP_POWER,
    BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_MIN_SUPPLY,
    BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_PASSIVE_COOLING,
    BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_WIFI_STATE,
    BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
    BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
    BOSCHCOM_ENDPOINT_ZONES,
    DEFAULT_TIMEOUT,
    JSON,
    MAX_BULK_ENDPOINTS,
    MAX_CONCURRENT,
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
from .model import (
    BHCDeviceCommodule,
    BHCDeviceGeneric,
    BHCDeviceIcom,
    BHCDeviceK40,
    BHCDeviceRac,
    BHCDeviceRrc2,
    BHCDeviceWddw2,
    ConnectionOptions,
)

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


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
                    _LOGGER.warning("Endpoint %s returned %s", endpoint, server_status)
                    continue
                device_endpoint_response = endpoint_response["gatewayResponse"]
                device_endpoint_response_status = device_endpoint_response["status"]
                if device_endpoint_response_status != HTTPStatus.OK.value:
                    _LOGGER.warning(
                        "Endpoint %s returned %s",
                        endpoint,
                        device_endpoint_response_status,
                    )
                    continue
                payload = device_endpoint_response["payload"]
                result[endpoint] = payload
        except (KeyError, IndexError, TypeError):
            return None
        else:
            return result

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
            "Authorization": f"Bearer {self._options.token}"  # Set Bearer token
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
                _LOGGER.warning("Endpoint %s returned %s", url, error.status)
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


class HomeComGeneric(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type generic."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize RAC device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "generic"

    async def async_update(self, device_id: str) -> BHCDeviceGeneric:
        """Retrieve data from the device."""
        await self.get_token()

        return BHCDeviceGeneric(
            device=device_id,
            firmware=[],
            notifications=[],
        )


class HomeComRac(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type rac."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize RAC device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "rac"

    async def async_get_stardard(self, device_id: str) -> Any:
        """Get get standard functions."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_STANDARD,
        )
        return await self._to_data(response)

    async def async_get_advanced(self, device_id: str) -> Any:
        """Get advanced functions."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ADVANCED,
        )
        return await self._to_data(response)

    async def async_get_switch(self, device_id: str) -> Any:
        """Get switch."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SWITCH,
        )
        return await self._to_data(response)

    async def async_update(self, device_id: str) -> BHCDeviceRac:
        """Retrieve data from the device using a single bulk request."""
        await self.get_token()

        bulk_response = await self.async_request_bulk(
            device_id,
            [
                BOSCHCOM_ENDPOINT_NOTIFICATIONS,
                BOSCHCOM_ENDPOINT_STANDARD,
                BOSCHCOM_ENDPOINT_ADVANCED,
                BOSCHCOM_ENDPOINT_SWITCH,
            ],
        )

        if bulk_response is None:
            bulk_response = {}

        notifications = bulk_response.get(BOSCHCOM_ENDPOINT_NOTIFICATIONS, {})
        stardard_functions = bulk_response.get(BOSCHCOM_ENDPOINT_STANDARD, {})
        advanced_functions = bulk_response.get(BOSCHCOM_ENDPOINT_ADVANCED, {})
        switch_programs = bulk_response.get(BOSCHCOM_ENDPOINT_SWITCH, {})

        return BHCDeviceRac(
            device=device_id,
            firmware=[],
            notifications=((notifications or {}).get("values") or []),
            stardard_functions=(stardard_functions or {}).get("references", []),
            advanced_functions=(advanced_functions or {}).get("references", []),
            switch_programs=(switch_programs or {}).get("references", []),
        )

    async def async_control(self, device_id: str, control: str) -> None:
        """Turn device on or off."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CONTROL,
            {"value": control},
            1,
        )

    async def async_control_program(self, device_id: str, control: str) -> None:
        """Turn program mode on or off."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SWITCH_ENABLE,
            {"value": control},
            1,
        )

    async def async_switch_program(self, device_id: str, program: str) -> None:
        """Set program."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SWITCH_PROGRAM,
            {"value": program},
            1,
        )

    async def async_time_on(self, device_id: str, time: int) -> None:
        """Set timer in minutes when device turns on."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_TIMER
            + "/on",
            {"value": time},
            1,
        )

    async def async_time_off(self, device_id: str, time: int) -> None:
        """Set timer in minutes when device turns off."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_TIMER
            + "/off",
            {"value": time},
            1,
        )

    async def async_turn_on(self, device_id: str) -> None:
        """Turn on."""
        await self.get_token()
        await self.async_control(device_id, "on")

    async def async_turn_off(self, device_id: str) -> None:
        """Turn off."""
        await self.get_token()
        await self.async_control(device_id, "off")

    async def async_set_temperature(self, device_id: str, temp: float) -> None:
        """Set new target temperature."""
        await self.get_token()

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_TEMP,
            {"value": round(temp, 1)},
            1,
        )

    async def async_set_hvac_mode(self, device_id: str, hvac_mode: str) -> None:
        """Set new hvac mode."""
        await self.get_token()

        payload = "off" if hvac_mode == "off" else "on"
        await self.async_control(device_id, payload)

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_MODE,
            {"value": hvac_mode},
            1,
        )

    async def async_set_plasmacluster(self, device_id: str, mode: bool) -> None:
        """Control plasmacluster."""
        await self.get_token()
        bool_to_status = {True: "on", False: "off"}

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_PLASMACLUSTER,
            {"value": bool_to_status[mode]},
            1,
        )

    async def async_set_boost(self, device_id: str, mode: bool) -> None:
        """Control full power."""
        await self.get_token()
        bool_to_status = {True: "on", False: "off"}

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_FULL_POWER,
            {"value": bool_to_status[mode]},
            1,
        )

    async def async_set_eco(self, device_id: str, mode: bool) -> None:
        """Control eco."""
        await self.get_token()
        bool_to_status = {True: "on", False: "off"}

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ECO,
            {"value": bool_to_status[mode]},
            1,
        )

    async def async_set_fan_mode(self, device_id: str, fan_mode: str) -> None:
        """Set fan mode."""
        await self.get_token()

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_FAN_SPEED,
            {"value": fan_mode},
            1,
        )

    async def async_set_vertical_swing_mode(
        self, device_id: str, swing_mode: str
    ) -> None:
        """Set vertical airflow swing mode."""
        await self.get_token()

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_AIRFLOW_VERTICAL,
            {"value": swing_mode},
            1,
        )

    async def async_set_horizontal_swing_mode(
        self, device_id: str, swing_mode: str
    ) -> None:
        """Set horizontal airflow swing mode."""
        await self.get_token()

        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_AIRFLOW_HORIZONTAL,
            {"value": swing_mode},
            1,
        )


class HomeComK40(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type k40."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize K40 device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "k40"

    async def async_get_dhw(self, device_id: str) -> Any:
        """Get hot water circuits."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
        )
        return await self._to_data(response)

    async def async_get_hc(self, device_id: str) -> Any:
        """Get heating circuits."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
        )
        return await self._to_data(response)

    async def async_get_hc_control_type(self, device_id: str, hc_id: str) -> Any:
        """Get hc control type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
        )
        return await self._to_data(response)

    async def async_get_hc_operation_mode(self, device_id: str, hc_id: str) -> Any:
        """Get hc control type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
        )
        return await self._to_data(response)

    async def async_put_hc_operation_mode(
        self, device_id: str, hc_id: str, mode: str
    ) -> None:
        """Set summer winter mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
            {"value": mode},
            1,
        )

    async def async_get_hc_suwi_mode(self, device_id: str, hc_id: str) -> Any:
        """Get hc summer winter mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
        )
        return await self._to_data(response)

    async def async_put_hc_suwi_mode(
        self, device_id: str, hc_id: str, mode: str
    ) -> None:
        """Set summer winter mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
            {"value": mode},
            1,
        )

    async def async_get_hc_heatcool_mode(self, device_id: str, hc_id: str) -> Any:
        """Get hc control type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
        )
        return await self._to_data(response)

    async def async_get_hc_room_temp(self, device_id: str, hc_id: str) -> Any:
        """Get hc control type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
        )
        return await self._to_data(response)

    async def async_get_hc_actual_humidity(self, device_id: str, hc_id: str) -> Any:
        """Get hc actual humidity."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY,
        )
        return await self._to_data(response)

    async def async_get_hc_manual_room_setpoint(
        self, device_id: str, hc_id: str
    ) -> Any:
        """Get hc manual room setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
        )
        return await self._to_data(response)

    async def async_get_hc_current_room_setpoint(
        self, device_id: str, hc_id: str
    ) -> Any:
        """Get hc current room setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
        )
        return await self._to_data(response)

    async def async_set_hc_manual_room_setpoint(
        self, device_id: str, hc_id: str, temp: str
    ) -> None:
        """Set hc manual room setpoint."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
            {"value": temp},
            1,
        )

    async def async_get_hc_cooling_room_temp_setpoint(
        self, device_id: str, hc_id: str
    ) -> Any:
        """Get hc cooling room temperature setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
        )
        return await self._to_data(response)

    async def async_set_hc_cooling_room_temp_setpoint(
        self, device_id: str, hc_id: str, temp: str
    ) -> None:
        """Set hc cooling room temperature setpoint."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
            {"value": temp},
            1,
        )

    async def async_put_hc_heatcool_mode(
        self, device_id: str, hc_id: str, mode: str
    ) -> None:
        """Turn heat cool mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
            {"value": mode},
            1,
        )

    async def async_get_hc_heating_type(self, device_id: str, hc_id: str) -> Any:
        """Get hc heating type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEATING_TYPE,
        )
        return await self._to_data(response)

    async def async_get_hs_total_consumption(self, device_id: str) -> Any:
        """Get heat source total consumption."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
        )
        return await self._to_data(response)

    async def async_get_consumption(
        self, device_id: str, component: str, date: str
    ) -> Any:
        """Get dhw current day consumption."""
        await self.get_token()
        response = await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN + BOSCHCOM_ENDPOINT_BULK,
            [
                {
                    "gatewayId": device_id,
                    "resourcePaths": [
                        f"/recordings/heatSources/emon/{component}/burner?interval={date}"
                    ],
                }
            ],
            1,
        )
        json_response = await self._to_data(response)
        if json_response is None:
            return None
        try:
            return json_response[0]["resourcePaths"][0]["gatewayResponse"]["payload"]
        except (KeyError, IndexError, TypeError):
            return json_response[0]["resourcePaths"][0]["gatewayResponse"]

    async def async_get_hs_type(self, device_id: str) -> Any:
        """Get heat source type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_TYPE,
        )
        return await self._to_data(response)

    async def async_get_hs_pump_type(self, device_id: str) -> Any:
        """Get heat source pump type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_PUMP_TYPE,
        )
        return await self._to_data(response)

    async def async_get_hs_starts(self, device_id: str) -> Any:
        """Get heat source number of starts."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_STARTS,
        )
        return await self._to_data(response)

    async def async_get_hs_return_temp(self, device_id: str) -> Any:
        """Get heat source return temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
        )
        return await self._to_data(response)

    async def async_get_hs_supply_temp(self, device_id: str) -> Any:
        """Get heat source actual supply temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
        )
        return await self._to_data(response)

    async def async_get_hs_modulation(self, device_id: str) -> Any:
        """Get heat source actual modulation."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_MODULATION,
        )
        return await self._to_data(response)

    async def async_get_hs_brine_inflow_temp(self, device_id: str) -> Any:
        """Get brine circuit collector inflow temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_INFLOW_TEMP,
        )
        return await self._to_data(response)

    async def async_get_hs_brine_outflow_temp(self, device_id: str) -> Any:
        """Get brine circuit collector outflow temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_OUTFLOW_TEMP,
        )
        return await self._to_data(response)

    async def async_get_hs_heat_demand(self, device_id: str) -> Any:
        """Get actual heat demand."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND,
        )
        return await self._to_data(response)

    async def async_get_hs_working_time(self, device_id: str) -> Any:
        """Get total working time."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
        )
        return await self._to_data(response)

    async def async_get_hs_system_pressure(self, device_id: str) -> Any:
        """Get heatSources system pressure."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE,
        )
        return await self._to_data(response)

    async def async_get_away_mode(self, device_id: str) -> Any:
        """Get away mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_AWAY_MODE,
        )
        return await self._to_data(response)

    async def async_put_away_mode(self, device_id: str, mode: str) -> None:
        """Set away mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_AWAY_MODE,
            {"value": mode},
            1,
        )

    async def async_get_holiday_mode(self, device_id: str) -> Any:
        """Get holiday mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HOLIDAY_MODE,
        )
        return await self._to_data(response)

    async def async_put_holiday_mode(self, device_id: str, mode: str) -> None:
        """Set holiday mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HOLIDAY_MODE,
            {"value": mode},
            1,
        )

    async def async_get_power_limitation(self, device_id: str) -> Any:
        """Get power limitation."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_POWER_LIMITATION,
        )
        return await self._to_data(response)

    async def async_get_outdoor_temp(self, device_id: str) -> Any:
        """Get power limitation."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
        )
        return await self._to_data(response)

    async def async_get_dhw_operation_mode(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
        )
        return await self._to_data(response)

    async def async_put_dhw_operation_mode(
        self, device_id: str, dhw_id: str, mode: str
    ) -> None:
        """Set dhw operation mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
            {"value": mode},
            1,
        )

    async def async_get_dhw_actual_temp(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw actual temp."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
        )
        return await self._to_data(response)

    async def async_get_dhw_temp_level(
        self, device_id: str, dhw_id: str, level: str
    ) -> Any:
        """Get dhw temp level."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL
            + "/"
            + level,
        )
        return await self._to_data(response)

    async def async_set_dhw_temp_level(
        self, device_id: str, dhw_id: str, level: str, temp: str
    ) -> None:
        """Get dhw temp level."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL
            + "/"
            + level,
            {"value": temp},
            1,
        )

    async def async_get_dhw_current_temp_level(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """Get dhw current temp level."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
        )
        return await self._to_data(response)

    async def async_put_dhw_current_temp_level(
        self, device_id: str, dhw_id: str, mode: str
    ) -> None:
        """Set dhw current temp level."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
            {"value": mode},
            1,
        )

    async def async_get_dhw_charge(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw charge."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE,
        )
        return await self._to_data(response)

    async def async_set_dhw_charge(
        self, device_id: str, dhw_id: str, value: str
    ) -> None:
        """Get dhw charge."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE,
            {"value": value},
            1,
        )

    async def async_get_dhw_charge_remaining_time(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """Get dhw charge remaining time."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
        )
        return await self._to_data(response)

    async def async_set_dhw_charge_duration(
        self, device_id: str, dhw_id: str, value: str
    ) -> None:
        """Get dhw charge remaining time."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
            {"value": value},
            1,
        )

    async def async_get_dhw_charge_duration(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw charge duration."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
        )
        return await self._to_data(response)

    async def async_get_dhw_charge_setpoint(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw charge setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
        )
        return await self._to_data(response)

    async def async_get_ventilation_zones(self, device_id: str) -> Any:
        """Get ventilation zones."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION,
        )
        return await self._to_data(response)

    async def async_get_ventilation_exhaustfanlevel(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation exhaust fan level."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_FAN,
        )
        return await self._to_data(response)

    async def async_get_ventilation_humidity(self, device_id: str, zone_id: str) -> Any:
        """Get ventilation max relative humidity."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_HUMIDITY,
        )
        return await self._to_data(response)

    async def async_get_ventilation_quality(self, device_id: str, zone_id: str) -> Any:
        """Get ventilation max indoor air quality."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_QUALITY,
        )
        return await self._to_data(response)

    async def async_get_ventilation_mode(self, device_id: str, zone_id: str) -> Any:
        """Get ventilation operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
        )
        return await self._to_data(response)

    async def async_set_ventilation_mode(
        self, device_id: str, zone_id: str, value: str
    ) -> Any:
        """Set ventilation operation mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
            {"value": value},
            1,
        )

    async def async_get_ventilation_exhaust_temp(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation exhaust temp."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_EXHAUST_TEMP,
        )
        return await self._to_data(response)

    async def async_get_ventilation_extract_temp(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation extract temp."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_EXTRACT_TEMP,
        )
        return await self._to_data(response)

    async def async_get_ventilation_internal_quality(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation internal quality."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_QUALITY,
        )
        return await self._to_data(response)

    async def async_get_ventilation_internal_humidity(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation internal humidity."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_HUMIDITY,
        )
        return await self._to_data(response)

    async def async_get_ventilation_outdoor_temp(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation outdoor temp."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_OUTDOOR_TEMP,
        )
        return await self._to_data(response)

    async def async_get_ventilation_supply_temp(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation supply temp."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP,
        )
        return await self._to_data(response)

    async def async_get_ventilation_summer_enable(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation summer enable."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE,
        )
        return await self._to_data(response)

    async def async_set_ventilation_summer_enable(
        self, device_id: str, zone_id: str, value: str
    ) -> Any:
        """Set ventilation summer enable."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE,
            {"value": value},
            1,
        )

    async def async_get_ventilation_summer_duration(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation summer duration."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION,
        )
        return await self._to_data(response)

    async def async_set_ventilation_summer_duration(
        self, device_id: str, zone_id: str, value: float
    ) -> Any:
        """Set ventilation summer duration in hours (floatValue, 1..12)."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION,
            {"value": round(value, 1)},
            1,
        )

    async def async_get_ventilation_summer_flap_power(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation summer-bypass flap power (auto-state diagnostic)."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_FLAP_POWER,
        )
        return await self._to_data(response)

    async def async_get_ventilation_summer_min_supply(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation summer-bypass minimum supply temperature threshold."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_MIN_SUPPLY,
        )
        return await self._to_data(response)

    async def async_get_ventilation_summer_passive_cooling(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation summer-bypass passive-cooling setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_PASSIVE_COOLING,
        )
        return await self._to_data(response)

    async def async_get_ventilation_demand_quality(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation demand indoor quality."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY,
        )
        return await self._to_data(response)

    async def async_set_ventilation_demand_quality(
        self, device_id: str, zone_id: str, value: str
    ) -> Any:
        """Set ventilation demand indoor quality."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY,
            {"value": value},
            1,
        )

    async def async_get_ventilation_demand_humidity(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get ventilation demand humidity."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY,
        )
        return await self._to_data(response)

    async def async_set_ventilation_demand_humidity(
        self, device_id: str, zone_id: str, value: str
    ) -> Any:
        """Set ventilation demand humidity."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_VENTILATION
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY,
            {"value": value},
            1,
        )

    async def async_get_zones(self, device_id: str) -> Any:
        """Get zones."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES,
        )
        # remove deviceTypeAllowed and list from value
        response_data = await self._to_data(response)
        if not response_data:
            return response_data
        references = response_data.get("references", [])
        response_data["references"] = [
            ref
            for ref in references
            if ref.get("id") not in ("/zones/deviceTypeAllowed", "/zones/list")
        ]
        return response_data

    async def async_get_zone_user_mode(self, device_id: str, zone_id: str) -> Any:
        """Get zone user mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
        )
        return await self._to_data(response)

    async def async_set_zone_user_mode(
        self, device_id: str, zone_id: str, mode: Literal["manual", "clock"]
    ) -> None:
        """Set zone user mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
            {"value": mode},
            1,
        )

    async def async_get_zone_temp_actual(self, device_id: str, zone_id: str) -> Any:
        """Get zone actual temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
        )
        return await self._to_data(response)

    async def async_get_zone_temp_setpoint(self, device_id: str, zone_id: str) -> Any:
        """Get zone temperature setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING,
        )
        return await self._to_data(response)

    async def async_get_zone_manual_temp_heating(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Get zone manual temperature heating."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
        )
        return await self._to_data(response)

    async def async_set_zone_manual_temp_heating(
        self, device_id: str, zone_id: str, temp: float
    ) -> None:
        """Set zone manual temperature heating."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
            {"value": temp},
            1,
        )

    async def async_get_hc_max_supply(self, device_id: str, hc_id: str) -> Any:
        """Get hc max supply temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
        )
        return await self._to_data(response)

    async def async_set_hc_max_supply(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc max supply temperature."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
            {"value": value},
            1,
        )

    async def async_get_hc_min_supply(self, device_id: str, hc_id: str) -> Any:
        """Get hc min supply temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
        )
        return await self._to_data(response)

    async def async_set_hc_min_supply(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc min supply temperature."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
            {"value": value},
            1,
        )

    async def async_get_hc_heat_curve_max(self, device_id: str, hc_id: str) -> Any:
        """Get hc heat curve max temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
        )
        return await self._to_data(response)

    async def async_set_hc_heat_curve_max(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc heat curve max temperature."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
            {"value": value},
            1,
        )

    async def async_get_hc_heat_curve_min(self, device_id: str, hc_id: str) -> Any:
        """Get hc heat curve min temperature."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
        )
        return await self._to_data(response)

    async def async_set_hc_heat_curve_min(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc heat curve min temperature."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
            {"value": value},
            1,
        )

    async def async_get_hc_supply_temp_setpoint(
        self, device_id: str, hc_id: str
    ) -> Any:
        """Get hc supply temperature setpoint."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT,
        )
        return await self._to_data(response)

    async def async_get_hc_night_switch_mode(self, device_id: str, hc_id: str) -> Any:
        """Get hc night switch mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
        )
        return await self._to_data(response)

    async def async_set_hc_night_switch_mode(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc night switch mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
            {"value": value},
            1,
        )

    async def async_get_hc_control(self, device_id: str, hc_id: str) -> Any:
        """Get hc control mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_CONTROL,
        )
        return await self._to_data(response)

    async def async_set_hc_control(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc control mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_CONTROL,
            {"value": value},
            1,
        )

    async def async_get_hc_night_threshold(self, device_id: str, hc_id: str) -> Any:
        """Get hc night threshold."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
        )
        return await self._to_data(response)

    async def async_set_hc_night_threshold(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc night threshold."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
            {"value": value},
            1,
        )

    async def async_get_hc_room_influence(self, device_id: str, hc_id: str) -> Any:
        """Get hc room influence."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
        )
        return await self._to_data(response)

    async def async_set_hc_room_influence(
        self, device_id: str, hc_id: str, value: str
    ) -> None:
        """Set hc room influence."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
            {"value": value},
            1,
        )

    async def async_get_hs_flame_indication(self, device_id: str) -> Any:
        """Get heat source flame indication."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_FLAME,
        )
        return await self._to_data(response)

    async def async_get_energy_history(
        self, device_id: str, entry: int | None = None
    ) -> Any:
        """Get energy history of the last 24 hours."""
        default_entries = 1
        index_offset = 1

        await self.get_token()

        if entry is None:
            entries = await self.async_get_energy_history_entries(device_id)

            if isinstance(entries, dict):
                entry = int(entries.get("value", default_entries)) - index_offset

        url = (
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ENERGY_HISTORY
        )

        if entry is not None:
            url += f"?entry={entry}"

        response = await self._async_http_request("get", url)
        return await self._to_data(response)

    async def async_get_energy_history_hourly(self, device_id: str) -> Any:
        """Get complete hourly energy history by following paginated next tokens."""
        await self.get_token()

        max_pages = 100
        all_entries: list[Any] = []
        first_page: dict[str, Any] | None = None
        next_cursor: int | str | None = None

        while max_pages > 0:
            max_pages -= 1

            url = (
                BOSCHCOM_DOMAIN
                + BOSCHCOM_ENDPOINT_GATEWAYS
                + device_id
                + BOSCHCOM_ENDPOINT_ENERGY_HISTORY_HOURLY
            )

            if next_cursor is not None:
                url += f"?next={next_cursor}"

            response = await self._async_http_request("get", url)
            page = await self._to_data(response)

            if not page:
                break

            if first_page is None:
                first_page = page

            page_values = page.get("value", [])

            if not page_values:
                break

            for value_item in page_values:
                all_entries.extend(value_item.get("entries", []))

            next_cursor = page_values[0].get("next")

            if next_cursor is None:
                break

        if first_page is None:
            return None

        result = dict(first_page)
        result["value"] = [{"entries": all_entries}]
        return result

    async def async_get_energy_gas_unit(self, device_id: str) -> Any:
        """Get energy gas unit."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ENERGY_GAS_UNIT,
        )
        return await self._to_data(response)

    async def async_get_energy_history_entries(self, device_id: str) -> Any:
        """Get the total number of available hourly energy history entries."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ENERGY_HISTORY_ENTRIES,
        )
        return await self._to_data(response)

    async def async_get_indoor_humidity(self, device_id: str) -> Any:
        """Get indoor humidity."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY,
        )
        return await self._to_data(response)

    async def async_get_devices_list(self, device_id: str) -> Any:
        """Get devices list."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DEVICES,
        )
        return await self._to_data(response)

    async def async_get_child_lock(self, device_id: str, dev_id: str) -> Any:
        """Get child lock status."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DEVICES
            + "/"
            + dev_id
            + BOSCHCOM_ENDPOINT_CHILD_LOCK,
        )
        return await self._to_data(response)

    async def async_set_child_lock(
        self, device_id: str, dev_id: str, value: str
    ) -> None:
        """Set child lock status."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DEVICES
            + "/"
            + dev_id
            + BOSCHCOM_ENDPOINT_CHILD_LOCK,
            {"value": value},
            1,
        )

    async def _async_get_device_property(
        self, device_id: str, dev_id: str, endpoint: str
    ) -> Any:
        """Get a property of a specific device."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DEVICES
            + "/"
            + dev_id
            + endpoint,
        )
        return await self._to_data(response)

    async def async_get_device_room_temp(self, device_id: str, dev_id: str) -> Any:
        """Get device room temperature."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_ROOM_TEMP
        )

    async def async_get_device_humidity(self, device_id: str, dev_id: str) -> Any:
        """Get device actual humidity."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_HUMIDITY
        )

    async def async_get_device_sgtin(self, device_id: str, dev_id: str) -> Any:
        """Get device SGTIN identifier."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_SGTIN
        )

    async def async_get_device_type(self, device_id: str, dev_id: str) -> Any:
        """Get device type."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_TYPE
        )

    async def async_get_device_signal(self, device_id: str, dev_id: str) -> Any:
        """Get device signal strength."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_SIGNAL
        )

    async def async_get_device_rf_status(self, device_id: str, dev_id: str) -> Any:
        """Get device RF connection status."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_RF_STATUS
        )

    async def async_get_device_battery(self, device_id: str, dev_id: str) -> Any:
        """Get device battery status."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_BATTERY
        )

    async def async_get_device_zone_id(self, device_id: str, dev_id: str) -> Any:
        """Get device zone ID."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_ZONE_ID
        )

    async def async_get_device_assigned_hc(self, device_id: str, dev_id: str) -> Any:
        """Get device assigned heating circuit."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_ASSIGNED_HC
        )

    async def async_get_device_operation_mode(self, device_id: str, dev_id: str) -> Any:
        """Get device operation mode."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_OPERATION_MODE
        )

    async def async_get_device_current_room_setpoint(
        self, device_id: str, dev_id: str
    ) -> Any:
        """Get device current room setpoint."""
        return await self._async_get_device_property(
            device_id, dev_id, BOSCHCOM_ENDPOINT_DEVICE_CURRENT_ROOM_SETPOINT
        )

    async def async_update(self, device_id: str) -> BHCDeviceK40:  # noqa: PLR0915
        """Retrieve data from the device concurrently with limited concurrency."""
        await self.get_token()

        semaphore = asyncio.BoundedSemaphore(MAX_CONCURRENT)

        async def limited_call(coro: Any) -> Any:
            async with semaphore:
                return await coro

        today = datetime.now(tz=UTC)

        notifications_task = asyncio.create_task(
            limited_call(self.async_get_notifications(device_id))
        )
        dhw_task = asyncio.create_task(limited_call(self.async_get_dhw(device_id)))
        heating_task = asyncio.create_task(limited_call(self.async_get_hc(device_id)))
        holiday_task = asyncio.create_task(
            limited_call(self.async_get_holiday_mode(device_id))
        )
        away_task = asyncio.create_task(
            limited_call(self.async_get_away_mode(device_id))
        )
        power_task = asyncio.create_task(
            limited_call(self.async_get_power_limitation(device_id))
        )
        outdoor_task = asyncio.create_task(
            limited_call(self.async_get_outdoor_temp(device_id))
        )
        ventilation_task = asyncio.create_task(
            limited_call(self.async_get_ventilation_zones(device_id))
        )
        zones_task = asyncio.create_task(limited_call(self.async_get_zones(device_id)))
        flame_task = asyncio.create_task(
            limited_call(self.async_get_hs_flame_indication(device_id))
        )
        energy_task = asyncio.create_task(
            limited_call(self.async_get_energy_history(device_id))
        )
        hourly_energy_task = asyncio.create_task(
            limited_call(self.async_get_energy_history_hourly(device_id))
        )
        energy_gas_unit_task = asyncio.create_task(
            limited_call(self.async_get_energy_gas_unit(device_id))
        )
        humidity_task = asyncio.create_task(
            limited_call(self.async_get_indoor_humidity(device_id))
        )
        devices_task = asyncio.create_task(
            limited_call(self.async_get_devices_list(device_id))
        )

        heat_sources_keys = [
            "pumpType",
            "starts",
            "returnTemperature",
            "actualSupplyTemperature",
            "actualModulation",
            "collectorInflowTemp",
            "collectorOutflowTemp",
            "actualHeatDemand",
            "totalWorkingTime",
            "consumption",
            "systemPressure",
        ]
        heat_sources_coros = [
            limited_call(self.async_get_hs_pump_type(device_id)),
            limited_call(self.async_get_hs_starts(device_id)),
            limited_call(self.async_get_hs_return_temp(device_id)),
            limited_call(self.async_get_hs_supply_temp(device_id)),
            limited_call(self.async_get_hs_modulation(device_id)),
            limited_call(self.async_get_hs_brine_inflow_temp(device_id)),
            limited_call(self.async_get_hs_brine_outflow_temp(device_id)),
            limited_call(self.async_get_hs_heat_demand(device_id)),
            limited_call(self.async_get_hs_working_time(device_id)),
            limited_call(self.async_get_hs_total_consumption(device_id)),
            limited_call(self.async_get_hs_system_pressure(device_id)),
        ]

        (
            notifications,
            dhw_circuits,
            heating_circuits,
            holiday_mode,
            away_mode,
            power_limitation,
            outdoor_temp,
            ventilation,
            zones,
            flame_indication,
            energy_history,
            hourly_energy_history,
            energy_gas_unit,
            indoor_humidity,
            devices,
            *heat_sources_values,
        ) = await asyncio.gather(
            notifications_task,
            dhw_task,
            heating_task,
            holiday_task,
            away_task,
            power_task,
            outdoor_task,
            ventilation_task,
            zones_task,
            flame_task,
            energy_task,
            hourly_energy_task,
            energy_gas_unit_task,
            humidity_task,
            devices_task,
            *heat_sources_coros,
        )

        heat_sources = {
            k: v or {}
            for k, v in zip(heat_sources_keys, heat_sources_values, strict=True)
        }
        heat_sources["flameIndication"] = flame_indication or {}

        (
            heat_sources["dayconsumption"],
            heat_sources["monthconsumption"],
            heat_sources["yearconsumption"],
        ) = await asyncio.gather(
            limited_call(
                self.async_get_consumption(
                    device_id, "total", today.strftime("%Y-%m-%d")
                )
            ),
            limited_call(
                self.async_get_consumption(device_id, "total", today.strftime("%Y-%m"))
            ),
            limited_call(
                self.async_get_consumption(device_id, "total", today.strftime("%Y"))
            ),
        )

        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                (
                    ref["operationMode"],
                    ref["actualTemp"],
                    ref["charge"],
                    ref["chargeRemainingTime"],
                    ref["currentTemperatureLevel"],
                    ref["singleChargeSetpoint"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_dhw_operation_mode(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_actual_temp(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_charge(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_charge_remaining_time(device_id, dhw_id)
                    ),
                    limited_call(
                        self.async_get_dhw_current_temp_level(device_id, dhw_id)
                    ),
                    limited_call(self.async_get_dhw_charge_setpoint(device_id, dhw_id)),
                )

                ref["tempLevel"] = {}
                ctl = ref.get("currentTemperatureLevel") or {}
                temp_tasks = [
                    limited_call(
                        self.async_get_dhw_temp_level(device_id, dhw_id, value)
                    )
                    for value in ctl.get("allowedValues", [])
                    if value != "off"
                ]
                if temp_tasks:
                    temp_results = await asyncio.gather(*temp_tasks)
                    for value, res in zip(
                        [v for v in ctl.get("allowedValues", []) if v != "off"],
                        temp_results,
                        strict=True,
                    ):
                        ref["tempLevel"][value] = res

                (
                    ref["dayconsumption"],
                    ref["monthconsumption"],
                    ref["yearconsumption"],
                ) = await asyncio.gather(
                    limited_call(
                        self.async_get_consumption(
                            device_id, "dhw", today.strftime("%Y-%m-%d")
                        )
                    ),
                    limited_call(
                        self.async_get_consumption(
                            device_id, "dhw", today.strftime("%Y-%m")
                        )
                    ),
                    limited_call(
                        self.async_get_consumption(
                            device_id, "dhw", today.strftime("%Y")
                        )
                    ),
                )

            await asyncio.gather(*(populate_dhw(ref) for ref in dhw_refs))
        else:
            dhw_circuits["references"] = {}

        heating_circuits = heating_circuits or {}
        hc_refs = heating_circuits.get("references", [])
        if hc_refs:

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                (
                    ref["operationMode"],
                    ref["currentSuWiMode"],
                    ref["heatCoolMode"],
                    ref["roomTemp"],
                    ref["actualHumidity"],
                    ref["manualRoomSetpoint"],
                    ref["currentRoomSetpoint"],
                    ref["coolingRoomTempSetpoint"],
                    ref["maxSupply"],
                    ref["minSupply"],
                    ref["heatCurveMax"],
                    ref["heatCurveMin"],
                    ref["supplyTemperatureSetpoint"],
                    ref["nightSwitchMode"],
                    ref["control"],
                    ref["nightThreshold"],
                    ref["roomInfluence"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_hc_operation_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_suwi_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_heatcool_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_room_temp(device_id, hc_id)),
                    limited_call(self.async_get_hc_actual_humidity(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_manual_room_setpoint(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_current_room_setpoint(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_cooling_room_temp_setpoint(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_max_supply(device_id, hc_id)),
                    limited_call(self.async_get_hc_min_supply(device_id, hc_id)),
                    limited_call(self.async_get_hc_heat_curve_max(device_id, hc_id)),
                    limited_call(self.async_get_hc_heat_curve_min(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_supply_temp_setpoint(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_night_switch_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_control(device_id, hc_id)),
                    limited_call(self.async_get_hc_night_threshold(device_id, hc_id)),
                    limited_call(self.async_get_hc_room_influence(device_id, hc_id)),
                )

                (
                    ref["dayconsumption"],
                    ref["monthconsumption"],
                    ref["yearconsumption"],
                ) = await asyncio.gather(
                    limited_call(
                        self.async_get_consumption(
                            device_id, "ch", today.strftime("%Y-%m-%d")
                        )
                    ),
                    limited_call(
                        self.async_get_consumption(
                            device_id, "ch", today.strftime("%Y-%m")
                        )
                    ),
                    limited_call(
                        self.async_get_consumption(
                            device_id, "ch", today.strftime("%Y")
                        )
                    ),
                )

            await asyncio.gather(*(populate_hc(ref) for ref in hc_refs))
        else:
            heating_circuits["references"] = {}

        vent_refs = (ventilation or {}).get("references", [])
        if vent_refs:

            async def populate_vent(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                (
                    ref["exhaustFanLevel"],
                    ref["maxIndoorAirQuality"],
                    ref["maxRelativeHumidity"],
                    ref["operationMode"],
                    ref["exhaustTemp"],
                    ref["extractTemp"],
                    ref["internalAirQuality"],
                    ref["internalHumidity"],
                    ref["outdoorTemp"],
                    ref["supplyTemp"],
                    ref["summerBypassEnable"],
                    ref["summerBypassDuration"],
                    ref["summerBypassFlapPower"],
                    ref["summerBypassMinSupply"],
                    ref["summerBypassPassiveCooling"],
                    ref["demandindoorAirQuality"],
                    ref["demandrelativeHumidity"],
                ) = await asyncio.gather(
                    limited_call(
                        self.async_get_ventilation_exhaustfanlevel(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_quality(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_humidity(device_id, zone_id)
                    ),
                    limited_call(self.async_get_ventilation_mode(device_id, zone_id)),
                    limited_call(
                        self.async_get_ventilation_exhaust_temp(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_extract_temp(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_internal_quality(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_internal_humidity(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_outdoor_temp(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_supply_temp(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_summer_enable(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_summer_duration(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_summer_flap_power(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_summer_min_supply(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_summer_passive_cooling(
                            device_id, zone_id
                        )
                    ),
                    limited_call(
                        self.async_get_ventilation_demand_quality(device_id, zone_id)
                    ),
                    limited_call(
                        self.async_get_ventilation_demand_humidity(device_id, zone_id)
                    ),
                )

            await asyncio.gather(*(populate_vent(ref) for ref in vent_refs))
        else:
            vent_refs = {}

        zone_refs = (zones or {}).get("references", [])
        if zone_refs:

            async def populate_zone(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                (
                    ref["userMode"],
                    ref["tempSetpoint"],
                    ref["temperatureActual"],
                    ref["manualTemperatureHeating"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_zone_user_mode(device_id, zone_id)),
                    limited_call(self.async_get_zone_temp_setpoint(device_id, zone_id)),
                    limited_call(self.async_get_zone_temp_actual(device_id, zone_id)),
                    limited_call(
                        self.async_get_zone_manual_temp_heating(device_id, zone_id)
                    ),
                )

            await asyncio.gather(*(populate_zone(ref) for ref in zone_refs))
        else:
            zone_refs = {}

        device_refs = (devices or {}).get("references", [])
        if device_refs:

            async def populate_device(ref: dict[str, Any]) -> None:
                dev_id = ref["id"].split("/")[-1]
                (
                    ref["childLock"],
                    ref["roomtemperature"],
                    ref["actualHumidity"],
                    ref["sgtin"],
                    ref["type"],
                    ref["signal"],
                    ref["rfConnectionStatus"],
                    ref["battery"],
                    ref["zoneId"],
                    ref["assignedHC"],
                    ref["operationMode"],
                    ref["currentRoomSetpoint"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_child_lock(device_id, dev_id)),
                    limited_call(self.async_get_device_room_temp(device_id, dev_id)),
                    limited_call(self.async_get_device_humidity(device_id, dev_id)),
                    limited_call(self.async_get_device_sgtin(device_id, dev_id)),
                    limited_call(self.async_get_device_type(device_id, dev_id)),
                    limited_call(self.async_get_device_signal(device_id, dev_id)),
                    limited_call(self.async_get_device_rf_status(device_id, dev_id)),
                    limited_call(self.async_get_device_battery(device_id, dev_id)),
                    limited_call(self.async_get_device_zone_id(device_id, dev_id)),
                    limited_call(self.async_get_device_assigned_hc(device_id, dev_id)),
                    limited_call(
                        self.async_get_device_operation_mode(device_id, dev_id)
                    ),
                    limited_call(
                        self.async_get_device_current_room_setpoint(device_id, dev_id)
                    ),
                )

            await asyncio.gather(*(populate_device(ref) for ref in device_refs))
        else:
            device_refs = {}

        return BHCDeviceK40(
            device=device_id,
            firmware=[],
            notifications=((notifications or {}).get("values") or []),
            holiday_mode=holiday_mode,
            away_mode=away_mode,
            power_limitation=power_limitation,
            outdoor_temp=outdoor_temp,
            heat_sources=heat_sources,
            dhw_circuits=dhw_circuits.get("references", {}),
            heating_circuits=heating_circuits.get("references", {}),
            ventilation=vent_refs,
            zones=zone_refs,
            flame_indication=flame_indication,
            energy_history=energy_history,
            hourly_energy_history=hourly_energy_history,
            energy_gas_unit=energy_gas_unit,
            indoor_humidity=indoor_humidity,
            devices=device_refs,
        )


class HomeComIcom(HomeComK40):
    """HomeCom client for icom heat pumps.

    Icom shares the /heatingCircuits, /dhwCircuits, /ventilation namespaces
    with K40 but exposes a much smaller endpoint set (no boost/away/cooling
    extras, no DHW charge, no heat-source telemetry beyond hs1/type+info, no
    recordings/energy, no humidity, no devices/zones, no PV/silentMode/etc).
    See homecom-api-endpoints.md sections "ICOM" vs "K30/K40".
    """

    async def async_get_heat_sources_info(self, device_id: str) -> Any:
        """Get the /heatSources/info payload."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + "/resource/heatSources/info",
        )
        return await self._to_data(response)

    async def async_get_solar_circuits(self, device_id: str) -> Any:
        """List solar circuits."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS,
        )
        return await self._to_data(response)

    async def async_get_system_info(self, device_id: str) -> Any:
        """Get system info payload."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_INFO,
        )
        return await self._to_data(response)

    async def async_get_system_bus(self, device_id: str) -> Any:
        """Get the system bus type."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_BUS,
        )
        return await self._to_data(response)

    async def async_get_system_holiday_modes(self, device_id: str) -> Any:
        """List system holiday-mode entries."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES,
        )
        return await self._to_data(response)

    async def _async_get_hm_field(self, device_id: str, hm_id: str, suffix: str) -> Any:
        """Read one sub-resource of a holiday-mode entry."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES
            + "/"
            + hm_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_hm_dhw_mode(self, device_id: str, hm_id: str) -> Any:
        """DHW mode for a holiday-mode entry."""
        return await self._async_get_hm_field(
            device_id, hm_id, BOSCHCOM_ENDPOINT_HM_DHW_MODE
        )

    async def async_get_hm_hc_mode(self, device_id: str, hm_id: str) -> Any:
        """HC mode for a holiday-mode entry."""
        return await self._async_get_hm_field(
            device_id, hm_id, BOSCHCOM_ENDPOINT_HM_HC_MODE
        )

    async def async_get_hm_fix_temperature(self, device_id: str, hm_id: str) -> Any:
        """Get fixed temperature for a holiday-mode entry."""
        return await self._async_get_hm_field(
            device_id, hm_id, BOSCHCOM_ENDPOINT_HM_FIX_TEMP
        )

    async def async_get_hm_start_stop(self, device_id: str, hm_id: str) -> Any:
        """Start/stop dates for a holiday-mode entry."""
        return await self._async_get_hm_field(
            device_id, hm_id, BOSCHCOM_ENDPOINT_HM_START_STOP
        )

    async def _async_get_hc_subresource(
        self, device_id: str, hc_id: str, suffix: str
    ) -> Any:
        """Read one sub-resource of a heating-circuit entry."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_hc_holiday_activated(self, device_id: str, hc_id: str) -> Any:
        """Per-HC holiday-mode activated flag."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED
        )

    async def async_get_hc_temperature_levels(self, device_id: str, hc_id: str) -> Any:
        """HC temperature-level presets root."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TEMPERATURE_LEVELS
        )

    async def async_get_hc_temp_level_comfort2(self, device_id: str, hc_id: str) -> Any:
        """HC comfort2 temperature level."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_COMFORT2
        )

    async def async_get_hc_temp_level_eco(self, device_id: str, hc_id: str) -> Any:
        """HC eco temperature level."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_ECO
        )

    async def async_get_hc_active_switch_program(
        self, device_id: str, hc_id: str
    ) -> Any:
        """HC active switch program."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM
        )

    async def async_get_hc_switch_program_a(self, device_id: str, hc_id: str) -> Any:
        """HC switch program A blob."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_A
        )

    async def async_get_hc_switch_program_b(self, device_id: str, hc_id: str) -> Any:
        """HC switch program B blob."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_B
        )

    async def async_get_hc_switch_program_mode(self, device_id: str, hc_id: str) -> Any:
        """HC switch program mode."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_MODE
        )

    async def async_get_hc_temporary_room_setpoint(
        self, device_id: str, hc_id: str
    ) -> Any:
        """HC temporary room setpoint."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT
        )

    async def async_get_hc_suwi_switch_mode(self, device_id: str, hc_id: str) -> Any:
        """HC summer/winter switch mode."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_SUWI_SWITCH_MODE
        )

    async def async_get_dhw_holiday_activated(self, device_id: str, dhw_id: str) -> Any:
        """Per-DHW holiday-mode activated flag."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DHW_HOLIDAY_ACTIVATED,
        )
        return await self._to_data(response)

    async def async_update(  # type: ignore[override]
        self, device_id: str
    ) -> BHCDeviceIcom:
        """Fetch the icom-supported endpoint subset and return a BHCDeviceIcom.

        Returns a different dataclass type than the inherited K40 method, so
        mypy needs to ignore the variance here. Treat coordinator code as
        polymorphic over BHCDeviceK40 | BHCDeviceIcom.
        """
        await self.get_token()

        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def limited_call(coro: Any) -> Any:
            async with sem:
                return await coro

        firmware = await self.async_get_firmware(device_id)

        (
            notifications,
            heating_circuits,
            dhw_circuits,
            solar_circuits,
            ventilation,
            holiday_modes,
            system_info,
            system_bus,
            hs_type,
            hs_info,
        ) = await asyncio.gather(
            limited_call(self.async_get_notifications(device_id)),
            limited_call(self.async_get_hc(device_id)),
            limited_call(self.async_get_dhw(device_id)),
            limited_call(self.async_get_solar_circuits(device_id)),
            limited_call(self.async_get_ventilation_zones(device_id)),
            limited_call(self.async_get_system_holiday_modes(device_id)),
            limited_call(self.async_get_system_info(device_id)),
            limited_call(self.async_get_system_bus(device_id)),
            limited_call(self.async_get_hs_type(device_id)),
            limited_call(self.async_get_heat_sources_info(device_id)),
        )

        heat_sources = {
            "type": hs_type or {},
            "info": hs_info or {},
        }

        # Heating circuits — fetch per-HC fields supported by icom.
        heating_circuits = heating_circuits or {}
        hc_refs = heating_circuits.get("references", [])
        if hc_refs:

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                (
                    ref["operationMode"],
                    ref["controlType"],
                    ref["currentSuWiMode"],
                    ref["suWiSwitchMode"],
                    ref["currentRoomSetpoint"],
                    ref["manualRoomSetpoint"],
                    ref["temporaryRoomSetpoint"],
                    ref["roomtemperature"],
                    ref["coolingRoomTempSetpoint"],
                    ref["holidayActivated"],
                    ref["temperatureLevels"],
                    ref["temperatureLevelComfort2"],
                    ref["temperatureLevelEco"],
                    ref["activeSwitchProgram"],
                    ref["switchProgramMode"],
                    ref["switchProgramA"],
                    ref["switchProgramB"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_hc_operation_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_control_type(device_id, hc_id)),
                    limited_call(self.async_get_hc_suwi_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_suwi_switch_mode(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_current_room_setpoint(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_manual_room_setpoint(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_temporary_room_setpoint(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_room_temp(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_cooling_room_temp_setpoint(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_holiday_activated(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_temperature_levels(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_temp_level_comfort2(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_temp_level_eco(device_id, hc_id)),
                    limited_call(
                        self.async_get_hc_active_switch_program(device_id, hc_id)
                    ),
                    limited_call(
                        self.async_get_hc_switch_program_mode(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_switch_program_a(device_id, hc_id)),
                    limited_call(self.async_get_hc_switch_program_b(device_id, hc_id)),
                )

            await asyncio.gather(*(populate_hc(ref) for ref in hc_refs))
        else:
            heating_circuits["references"] = []

        # DHW circuits — only listing + per-circuit holiday flag.
        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                ref["holidayActivated"] = await limited_call(
                    self.async_get_dhw_holiday_activated(device_id, dhw_id)
                )

            await asyncio.gather(*(populate_dhw(ref) for ref in dhw_refs))
        else:
            dhw_circuits["references"] = []

        # Solar circuits — listing only (per spec).
        solar_circuits = solar_circuits or {}
        solar_refs = solar_circuits.get("references", [])

        # Ventilation — only fan level + operation mode per zone.
        ventilation = ventilation or {}
        vent_refs = ventilation.get("references", [])
        if vent_refs:

            async def populate_vent(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                (
                    ref["exhaustFanLevel"],
                    ref["operationMode"],
                ) = await asyncio.gather(
                    limited_call(
                        self.async_get_ventilation_exhaustfanlevel(device_id, zone_id)
                    ),
                    limited_call(self.async_get_ventilation_mode(device_id, zone_id)),
                )

            await asyncio.gather(*(populate_vent(ref) for ref in vent_refs))

        # Holiday modes — for each hm{N} fetch dhwMode/hcMode/fixTemperature/startStop.
        holiday_modes = holiday_modes or {}
        hm_refs = holiday_modes.get("references", [])
        if hm_refs:

            async def populate_hm(ref: dict[str, Any]) -> None:
                hm_id = ref["id"].split("/")[-1]
                (
                    ref["dhwMode"],
                    ref["hcMode"],
                    ref["fixTemperature"],
                    ref["startStop"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_hm_dhw_mode(device_id, hm_id)),
                    limited_call(self.async_get_hm_hc_mode(device_id, hm_id)),
                    limited_call(self.async_get_hm_fix_temperature(device_id, hm_id)),
                    limited_call(self.async_get_hm_start_stop(device_id, hm_id)),
                )

            await asyncio.gather(*(populate_hm(ref) for ref in hm_refs))

        return BHCDeviceIcom(
            device=device_id,
            firmware=firmware,
            notifications=(notifications or {}).get("values") or [],
            holiday_mode=hm_refs,
            heat_sources=heat_sources,
            dhw_circuits=dhw_refs,
            heating_circuits=hc_refs,
            solar_circuits=solar_refs,
            ventilation=vent_refs,
            system_info=system_info or {},
            system_bus=system_bus or {},
        )


class HomeComRrc2(HomeComAlt):
    """HomeCom client for rrc2 (Remeha Remote Control) gateways.

    Distinct URL scheme from K40 — uses /zones, /hc, /dhw paths and a much
    smaller surface (no heatingCircuits, no system/info, no recordings).
    """

    def __init__(
        self,
        session: ClientSession,
        options: Any,
        device_id: str,
        auth_provider: bool,
    ) -> None:
        """Initialize Rrc2 device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "rrc2"

    async def async_get_rrc2_zones(self, device_id: str) -> Any:
        """List rrc2 zones."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_ZONES,
        )
        return await self._to_data(response)

    async def _async_get_zone_field(
        self, device_id: str, zone_id: str, suffix: str
    ) -> Any:
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_ZONES
            + "/"
            + zone_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_zone_temp_actual(self, device_id: str, zone_id: str) -> Any:
        """Actual zone temperature."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_RRC2_ZONE_TEMP_ACTUAL
        )

    async def async_get_zone_temp_heating_setpoint(
        self, device_id: str, zone_id: str
    ) -> Any:
        """Zone heating setpoint."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_RRC2_ZONE_TEMP_HEATING_SETPOINT
        )

    async def async_get_zone_name(self, device_id: str, zone_id: str) -> Any:
        """Zone name."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_RRC2_ZONE_NAME
        )

    async def async_get_zone_icon(self, device_id: str, zone_id: str) -> Any:
        """Zone icon identifier."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_RRC2_ZONE_ICON
        )

    async def _async_get_hc_field(self, device_id: str, hc_id: str, suffix: str) -> Any:
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_HC
            + "/"
            + hc_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_hc_actual_temp(self, device_id: str, hc_id: str) -> Any:
        """Heating circuit actual temperature (rrc2 path)."""
        return await self._async_get_hc_field(
            device_id, hc_id, BOSCHCOM_ENDPOINT_RRC2_HC_ACTUAL_TEMP
        )

    async def async_get_hc_control_key(self, device_id: str, hc_id: str) -> Any:
        """Heating circuit control key."""
        return await self._async_get_hc_field(
            device_id, hc_id, BOSCHCOM_ENDPOINT_RRC2_HC_CONTROL_KEY
        )

    async def _async_get_dhw_field(
        self, device_id: str, dhw_id: str, suffix: str
    ) -> Any:
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_DHW
            + "/"
            + dhw_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_dhw_actual_temp(self, device_id: str, dhw_id: str) -> Any:
        """DHW actual temperature (rrc2 path)."""
        return await self._async_get_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_RRC2_DHW_ACTUAL_TEMP
        )

    async def async_get_dhw_hot_water_system(self, device_id: str, dhw_id: str) -> Any:
        """DHW hot water system info."""
        return await self._async_get_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_RRC2_DHW_HOT_WATER_SYSTEM
        )

    async def async_get_gateway_uuid(self, device_id: str) -> Any:
        """Gateway UUID."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID,
        )
        return await self._to_data(response)

    async def async_get_gateway_time(self, device_id: str) -> Any:
        """Gateway current time."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME,
        )
        return await self._to_data(response)

    async def async_get_gateway_timezone(self, device_id: str) -> Any:
        """Gateway timezone."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE,
        )
        return await self._to_data(response)

    async def async_get_system_location(self, device_id: str) -> Any:
        """System location coordinates."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION,
        )
        return await self._to_data(response)

    async def async_update(self, device_id: str) -> BHCDeviceRrc2:
        """Fetch the rrc2-supported endpoint subset and return a BHCDeviceRrc2."""
        await self.get_token()

        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def limited_call(coro: Any) -> Any:
            async with sem:
                return await coro

        firmware = await self.async_get_firmware(device_id)

        (
            notifications,
            zones,
            gw_uuid,
            gw_time,
            gw_timezone,
            system_location,
        ) = await asyncio.gather(
            limited_call(self.async_get_notifications(device_id)),
            limited_call(self.async_get_rrc2_zones(device_id)),
            limited_call(self.async_get_gateway_uuid(device_id)),
            limited_call(self.async_get_gateway_time(device_id)),
            limited_call(self.async_get_gateway_timezone(device_id)),
            limited_call(self.async_get_system_location(device_id)),
        )

        zones = zones or {}
        zone_refs = zones.get("references", [])
        hc_refs: list[dict[str, Any]] = []
        dhw_refs: list[dict[str, Any]] = []

        if zone_refs:

            async def populate_zone(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                (
                    ref["zoneTemperatureActual"],
                    ref["zoneTemperatureHeatingSetpoint"],
                    ref["name"],
                    ref["icon"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_zone_temp_actual(device_id, zone_id)),
                    limited_call(
                        self.async_get_zone_temp_heating_setpoint(device_id, zone_id)
                    ),
                    limited_call(self.async_get_zone_name(device_id, zone_id)),
                    limited_call(self.async_get_zone_icon(device_id, zone_id)),
                )

            await asyncio.gather(*(populate_zone(ref) for ref in zone_refs))

            # rrc2 returns hc{N} and dhw{N} ids implicit per zone — derive a
            # synthetic listing by scanning zone metadata. Real installs may
            # have only one of each; we surface them as separate refs so HA
            # can wire HC/DHW entities.
            hc_refs = [{"id": f"/hc/hc{i}"} for i in range(1, len(zone_refs) + 1)][:1]
            dhw_refs = [{"id": "/dhw/dhw1"}]

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                (
                    ref["actualTemperature"],
                    ref["controlKey"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_hc_actual_temp(device_id, hc_id)),
                    limited_call(self.async_get_hc_control_key(device_id, hc_id)),
                )

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                (
                    ref["actualTemperature"],
                    ref["hotWaterSystem"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_dhw_actual_temp(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_hot_water_system(device_id, dhw_id)
                    ),
                )

            await asyncio.gather(
                *(populate_hc(ref) for ref in hc_refs),
                *(populate_dhw(ref) for ref in dhw_refs),
            )

        gateway_info = {
            "uuid": gw_uuid or {},
            "time": gw_time or {},
            "timezone": gw_timezone or {},
        }

        return BHCDeviceRrc2(
            device=device_id,
            firmware=firmware,
            notifications=(notifications or {}).get("values") or [],
            zones=zone_refs,
            heating_circuits=hc_refs,
            dhw_circuits=dhw_refs,
            gateway_info=gateway_info,
            system_location=system_location or {},
        )


class HomeComWddw2(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type wddw2."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize wddw2 device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "wddw2"

    async def async_get_dhw(self, device_id: str) -> Any:
        """Get hot water circuits."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
        )
        return await self._to_data(response)

    async def async_get_dhw_operation_mode(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
        )
        return await self._to_data(response)

    async def async_put_dhw_operation_mode(
        self, device_id: str, dhw_id: str, mode: str
    ) -> None:
        """Set dhw operation mode."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
            {"value": mode},
            1,
        )

    async def async_get_dhw_temp_level(
        self, device_id: str, dhw_id: str, level: str
    ) -> Any:
        """Get dhw temp level."""
        await self.get_token()
        if level == "manual":
            response = await self._async_http_request(
                "get",
                BOSCHCOM_DOMAIN
                + BOSCHCOM_ENDPOINT_GATEWAYS
                + device_id
                + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
                + "/"
                + dhw_id
                + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_MANUAL,
            )
        else:
            response = await self._async_http_request(
                "get",
                BOSCHCOM_DOMAIN
                + BOSCHCOM_ENDPOINT_GATEWAYS
                + device_id
                + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
                + "/"
                + dhw_id
                + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL
                + "/"
                + level,
            )
        return await self._to_data(response)

    async def async_set_dhw_temp_level(
        self,
        device_id: str,
        dhw_id: str,
        level: str,  # noqa: ARG002
        temp: float,
    ) -> None:
        """Get dhw temp level."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_MANUAL,
            {"value": round(temp, 1)},
            1,
        )

    async def async_get_dhw_airbox_temp(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_AIRBOX,
        )
        return await self._to_data(response)

    async def async_get_dhw_fan_speed(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_FAN_SPEED,
        )
        return await self._to_data(response)

    async def async_get_dhw_inlet_temp(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_INLET_TEMP,
        )
        return await self._to_data(response)

    async def async_get_dhw_outlet_temp(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_OUTLET_TEMP,
        )
        return await self._to_data(response)

    async def async_get_dhw_water_flow(self, device_id: str, dhw_id: str) -> Any:
        """Get dhw operation mode."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_WATER_FLOW,
        )
        return await self._to_data(response)

    async def async_get_hs_starts(self, device_id: str) -> Any:
        """Get heat source number of starts."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_STARTS,
        )
        return await self._to_data(response)

    async def async_update(self, device_id: str) -> BHCDeviceWddw2:
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        dhw_circuits = await self.async_get_dhw(device_id)
        dhw_circuits = dhw_circuits or {}
        references = dhw_circuits.get("references", [])
        if references:
            for ref in references:
                dhw_id = ref["id"].split("/")[-1]
                if re.fullmatch(r"dhw\d", dhw_id):
                    ref["operationMode"] = await self.async_get_dhw_operation_mode(
                        device_id, dhw_id
                    )
                    ref["airBoxTemperature"] = await self.async_get_dhw_airbox_temp(
                        device_id, dhw_id
                    )
                    ref["fanSpeed"] = await self.async_get_dhw_fan_speed(
                        device_id, dhw_id
                    )
                    ref["inletTemperature"] = await self.async_get_dhw_inlet_temp(
                        device_id, dhw_id
                    )
                    ref["outletTemperature"] = await self.async_get_dhw_outlet_temp(
                        device_id, dhw_id
                    )
                    ref["waterFlow"] = await self.async_get_dhw_water_flow(
                        device_id, dhw_id
                    )
                    ref["nbStarts"] = await self.async_get_hs_starts(device_id)
                    ref["tempLevel"] = {}
                    ctl = ref.get("operationMode") or {}
                    for value in ctl.get("allowedValues", []):
                        if value != "off":
                            ref["tempLevel"][
                                value
                            ] = await self.async_get_dhw_temp_level(
                                device_id, dhw_id, value
                            )
        else:
            dhw_circuits["references"] = {}

        return BHCDeviceWddw2(
            device=device_id,
            firmware=[],
            notifications=((notifications or {}).get("values") or []),
            dhw_circuits=dhw_circuits.get("references", {}),
        )


class HomeComCommodule(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type commodule."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize commodule device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "commodule"

    async def async_get_charge_points(self, device_id: str) -> Any:
        """Get charge points."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP,
        )
        return await self._to_data(response)

    async def async_get_cp_conf(self, device_id: str, cp_id: str) -> Any:
        """Get charge point configuration."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF,
        )
        return await self._to_data(response)

    async def async_get_cp_info(self, device_id: str, cp_id: str) -> Any:
        """Get charge point info."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_INFO,
        )
        return await self._to_data(response)

    async def async_get_cp_telemetry(self, device_id: str, cp_id: str) -> Any:
        """Get charge point telemetry."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_TELEMETRY,
        )
        return await self._to_data(response)

    async def async_get_cp_chargelog(self, device_id: str, cp_id: str) -> Any:
        """Get charge point charge log."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CHARGELOG,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_price(self, device_id: str, cp_id: str) -> Any:
        """Get charge point electricity price."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_locked(self, device_id: str, cp_id: str) -> Any:
        """Get charge point lock state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_auth(self, device_id: str, cp_id: str) -> Any:
        """Get charge point auth setting."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_rfid_secure(self, device_id: str, cp_id: str) -> Any:
        """Get charge point RFID security setting."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
        )
        return await self._to_data(response)

    async def async_get_eth0_state(self, device_id: str) -> Any:
        """Get ethernet connection state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ETH0_STATE,
        )
        return await self._to_data(response)

    async def async_get_wifi_state(self, device_id: str) -> Any:
        """Get wifi connection state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_WIFI_STATE,
        )
        return await self._to_data(response)

    async def async_put_cp_conf_price(
        self, device_id: str, cp_id: str, price: float
    ) -> None:
        """Set charge point electricity price."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
            {"value": round(price, 2)},
            1,
        )

    async def async_put_cp_conf_locked(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point lock state."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
            {"value": value},
            1,
        )

    async def async_put_cp_conf_auth(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point auth setting."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
            {"value": value},
            1,
        )

    async def async_put_cp_conf_rfid_secure(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point RFID security setting."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
            {"value": value},
            1,
        )

    async def async_cp_authenticate(
        self, device_id: str, cp_id: str, name: str
    ) -> None:
        """Authenticate on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_AUTHENTICATE,
            {"name": name},
            1,
        )

    async def async_cp_start_charging(
        self, device_id: str, cp_id: str, label: str
    ) -> None:
        """Start charging on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_START,
            {"name": label},
            1,
        )

    async def async_cp_pause_charging(
        self, device_id: str, cp_id: str, label: str
    ) -> None:
        """Pause charging on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_PAUSE,
            {"name": label},
            1,
        )

    async def async_cp_set_limit(self, device_id: str, cp_id: str, limit: int) -> None:
        """Set charging limit on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_LIMIT,
            {"limit": limit},
            1,
        )

    async def async_update(self, device_id: str) -> BHCDeviceCommodule:
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        eth0_state = await self.async_get_eth0_state(device_id)
        wifi_state = await self.async_get_wifi_state(device_id)
        charge_points_data = await self.async_get_charge_points(device_id)
        charge_points_data = charge_points_data or {}
        references = charge_points_data.get("references", [])
        if references:
            for ref in references:
                cp_id = ref["id"].split("/")[-1]
                if re.fullmatch(r"cp\d+", cp_id):
                    ref["conf"] = await self.async_get_cp_conf(device_id, cp_id)
                    ref["info"] = await self.async_get_cp_info(device_id, cp_id)
                    ref["telemetry"] = await self.async_get_cp_telemetry(
                        device_id, cp_id
                    )
                    ref["chargelog"] = await self.async_get_cp_chargelog(
                        device_id, cp_id
                    )
                    ref["price"] = await self.async_get_cp_conf_price(device_id, cp_id)
                    ref["locked"] = await self.async_get_cp_conf_locked(
                        device_id, cp_id
                    )
                    ref["auth"] = await self.async_get_cp_conf_auth(device_id, cp_id)
                    ref["rfidSecure"] = await self.async_get_cp_conf_rfid_secure(
                        device_id, cp_id
                    )
        else:
            charge_points_data["references"] = {}

        return BHCDeviceCommodule(
            device=device_id,
            firmware=[],
            notifications=((notifications or {}).get("values") or []),
            charge_points=charge_points_data.get("references", {}),
            eth0_state=eth0_state,
            wifi_state=wifi_state,
        )
