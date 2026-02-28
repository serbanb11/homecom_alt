"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any
from urllib.parse import urlencode

import jwt
from aiohttp import (
    ClientConnectorError,
    ClientResponseError,
    ClientSession,
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
    BOSCHCOM_ENDPOINT_CP_CONF,
    BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
    BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
    BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
    BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
    BOSCHCOM_ENDPOINT_CP_INFO,
    BOSCHCOM_ENDPOINT_CP_TELEMETRY,
    BOSCHCOM_ENDPOINT_DEVICES,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
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
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY,
    BOSCHCOM_ENDPOINT_ETH0_STATE,
    BOSCHCOM_ENDPOINT_FAN_SPEED,
    BOSCHCOM_ENDPOINT_FIRMWARE,
    BOSCHCOM_ENDPOINT_FULL_POWER,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY,
    BOSCHCOM_ENDPOINT_HC_CONTROL,
    BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
    BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
    BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
    BOSCHCOM_ENDPOINT_HC_HEATING_TYPE,
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
    BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
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
    BOSCHCOM_ENDPOINT_STANDARD,
    BOSCHCOM_ENDPOINT_SWITCH,
    BOSCHCOM_ENDPOINT_SWITCH_ENABLE,
    BOSCHCOM_ENDPOINT_SWITCH_PROGRAM,
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
    BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
    BOSCHCOM_ENDPOINT_ZONES,
    DEFAULT_TIMEOUT,
    JSON,
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
    BHCDeviceK40,
    BHCDeviceRac,
    BHCDeviceWddw2,
    ConnectionOptions,
)

_LOGGER = logging.getLogger(__name__)


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

    async def _async_http_request(
        self,
        method: str,
        url: str,
        data: Any | None = None,
        req_type: int | None = None,
    ) -> Any:
        """Retrieve data from the device."""
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
            if error.status in (
                HTTPStatus.NOT_FOUND.value,  # 404
                HTTPStatus.FORBIDDEN.value,  # 403
            ):
                # This url is not support for this type of device, just ignore it
                return {}
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
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

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
                        raise InvalidSensorDataError("Invalid devices data") from error

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
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        stardard_functions = await self.async_get_stardard(device_id)
        advanced_functions = await self.async_get_advanced(device_id)
        switch_programs = await self.async_get_switch(device_id)
        return BHCDeviceRac(
            device=device_id,
            firmware=[],
            notifications=notifications.get("values", []),
            stardard_functions=stardard_functions["references"],
            advanced_functions=advanced_functions["references"],
            switch_programs=switch_programs["references"],
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
        self, device_id: str, zone_id: str, value: str
    ) -> Any:
        """Set ventilation summer duration."""
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
            {"value": value},
            1,
        )

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
        return await self._to_data(response)

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

    async def async_get_energy_history(self, device_id: str) -> Any:
        """Get energy history."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ENERGY_HISTORY,
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

    async def async_update(self, device_id: str) -> BHCDeviceK40:  # noqa: PLR0912, PLR0915
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        dhw_circuits = await self.async_get_dhw(device_id)
        references = dhw_circuits.get("references", [])
        if references:
            for ref in references:
                dhw_id = ref["id"].split("/")[-1]
                ref["operationMode"] = await self.async_get_dhw_operation_mode(
                    device_id, dhw_id
                )
                ref["actualTemp"] = await self.async_get_dhw_actual_temp(
                    device_id, dhw_id
                )
                ref["charge"] = await self.async_get_dhw_charge(device_id, dhw_id)
                ref[
                    "chargeRemainingTime"
                ] = await self.async_get_dhw_charge_remaining_time(device_id, dhw_id)
                ref[
                    "currentTemperatureLevel"
                ] = await self.async_get_dhw_current_temp_level(device_id, dhw_id)
                ref["singleChargeSetpoint"] = await self.async_get_dhw_charge_setpoint(
                    device_id, dhw_id
                )
                ref["tempLevel"] = {}
                ctl = ref.get("currentTemperatureLevel") or {}
                for value in ctl.get("allowedValues", []):
                    if value != "off":
                        ref["tempLevel"][value] = await self.async_get_dhw_temp_level(
                            device_id, dhw_id, value
                        )
                ref["dayconsumption"] = await self.async_get_consumption(
                    device_id, "dhw", datetime.now(tz=UTC).strftime("%Y-%m-%d")
                )
                ref["monthconsumption"] = await self.async_get_consumption(
                    device_id, "dhw", datetime.now(tz=UTC).strftime("%Y-%m")
                )
                ref["yearconsumption"] = await self.async_get_consumption(
                    device_id, "dhw", datetime.now(tz=UTC).strftime("%Y")
                )
        else:
            dhw_circuits["references"] = {}

        heating_circuits = await self.async_get_hc(device_id)
        references = heating_circuits.get("references", [])
        if references:
            for ref in references:
                hc_id = ref["id"].split("/")[-1]
                ref["operationMode"] = await self.async_get_hc_operation_mode(
                    device_id, hc_id
                )
                ref["currentSuWiMode"] = await self.async_get_hc_suwi_mode(
                    device_id, hc_id
                )
                ref["heatCoolMode"] = await self.async_get_hc_heatcool_mode(
                    device_id, hc_id
                )
                ref["roomTemp"] = await self.async_get_hc_room_temp(device_id, hc_id)
                ref["actualHumidity"] = await self.async_get_hc_actual_humidity(
                    device_id, hc_id
                )
                ref[
                    "manualRoomSetpoint"
                ] = await self.async_get_hc_manual_room_setpoint(device_id, hc_id)
                ref[
                    "currentRoomSetpoint"
                ] = await self.async_get_hc_current_room_setpoint(device_id, hc_id)
                ref[
                    "coolingRoomTempSetpoint"
                ] = await self.async_get_hc_cooling_room_temp_setpoint(device_id, hc_id)
                ref["maxSupply"] = await self.async_get_hc_max_supply(device_id, hc_id)
                ref["minSupply"] = await self.async_get_hc_min_supply(device_id, hc_id)
                ref["heatCurveMax"] = await self.async_get_hc_heat_curve_max(
                    device_id, hc_id
                )
                ref["heatCurveMin"] = await self.async_get_hc_heat_curve_min(
                    device_id, hc_id
                )
                ref[
                    "supplyTemperatureSetpoint"
                ] = await self.async_get_hc_supply_temp_setpoint(device_id, hc_id)
                ref["nightSwitchMode"] = await self.async_get_hc_night_switch_mode(
                    device_id, hc_id
                )
                ref["control"] = await self.async_get_hc_control(device_id, hc_id)
                ref["nightThreshold"] = await self.async_get_hc_night_threshold(
                    device_id, hc_id
                )
                ref["roomInfluence"] = await self.async_get_hc_room_influence(
                    device_id, hc_id
                )
                ref["dayconsumption"] = await self.async_get_consumption(
                    device_id, "ch", datetime.now(tz=UTC).strftime("%Y-%m-%d")
                )
                ref["monthconsumption"] = await self.async_get_consumption(
                    device_id, "ch", datetime.now(tz=UTC).strftime("%Y-%m")
                )
                ref["yearconsumption"] = await self.async_get_consumption(
                    device_id, "ch", datetime.now(tz=UTC).strftime("%Y")
                )
        else:
            heating_circuits["references"] = {}

        heat_sources = {}
        heat_sources["pumpType"] = await self.async_get_hs_pump_type(device_id) or {}
        heat_sources["starts"] = await self.async_get_hs_starts(device_id) or {}
        heat_sources["returnTemperature"] = (
            await self.async_get_hs_return_temp(device_id) or {}
        )
        heat_sources["actualSupplyTemperature"] = (
            await self.async_get_hs_supply_temp(device_id) or {}
        )
        heat_sources["actualModulation"] = (
            await self.async_get_hs_modulation(device_id) or {}
        )
        heat_sources["collectorInflowTemp"] = (
            await self.async_get_hs_brine_inflow_temp(device_id) or {}
        )
        heat_sources["collectorOutflowTemp"] = (
            await self.async_get_hs_brine_outflow_temp(device_id) or {}
        )
        heat_sources["actualHeatDemand"] = (
            await self.async_get_hs_heat_demand(device_id) or {}
        )
        heat_sources["totalWorkingTime"] = (
            await self.async_get_hs_working_time(device_id) or {}
        )
        # It should actually be called totalconsumption, but for
        # compatibility reasons it remains consumption.
        heat_sources["consumption"] = (
            await self.async_get_hs_total_consumption(device_id) or {}
        )
        heat_sources["dayconsumption"] = await self.async_get_consumption(
            device_id, "total", datetime.now(tz=UTC).strftime("%Y-%m-%d")
        )
        heat_sources["monthconsumption"] = await self.async_get_consumption(
            device_id, "total", datetime.now(tz=UTC).strftime("%Y-%m")
        )
        heat_sources["yearconsumption"] = await self.async_get_consumption(
            device_id, "total", datetime.now(tz=UTC).strftime("%Y")
        )
        heat_sources["systemPressure"] = (
            await self.async_get_hs_system_pressure(device_id) or {}
        )
        holiday_mode = await self.async_get_holiday_mode(device_id)
        away_mode = await self.async_get_away_mode(device_id)
        power_limitation = await self.async_get_power_limitation(device_id)
        outdoor_temp = await self.async_get_outdoor_temp(device_id)

        ventilation = await self.async_get_ventilation_zones(device_id)
        ventilation_references = (ventilation or {}).get("references", [])
        if ventilation_references:
            for ref in ventilation_references:
                zone_id = ref["id"].split("/")[-1]
                ref[
                    "exhaustFanLevel"
                ] = await self.async_get_ventilation_exhaustfanlevel(device_id, zone_id)
                ref["maxIndoorAirQuality"] = await self.async_get_ventilation_quality(
                    device_id, zone_id
                )
                ref["maxRelativeHumidity"] = await self.async_get_ventilation_humidity(
                    device_id, zone_id
                )
                ref["operationMode"] = await self.async_get_ventilation_mode(
                    device_id, zone_id
                )
                ref["exhaustTemp"] = await self.async_get_ventilation_exhaust_temp(
                    device_id, zone_id
                )
                ref["extractTemp"] = await self.async_get_ventilation_extract_temp(
                    device_id, zone_id
                )
                ref[
                    "internalAirQuality"
                ] = await self.async_get_ventilation_internal_quality(
                    device_id, zone_id
                )
                ref[
                    "internalHumidity"
                ] = await self.async_get_ventilation_internal_humidity(
                    device_id, zone_id
                )
                ref["outdoorTemp"] = await self.async_get_ventilation_outdoor_temp(
                    device_id, zone_id
                )
                ref["supplyTemp"] = await self.async_get_ventilation_supply_temp(
                    device_id, zone_id
                )
                ref[
                    "summerBypassEnable"
                ] = await self.async_get_ventilation_summer_enable(device_id, zone_id)
                ref[
                    "summerBypassDuration"
                ] = await self.async_get_ventilation_summer_duration(device_id, zone_id)
                ref[
                    "demandindoorAirQuality"
                ] = await self.async_get_ventilation_demand_quality(device_id, zone_id)
                ref[
                    "demandrelativeHumidity"
                ] = await self.async_get_ventilation_demand_humidity(device_id, zone_id)
        else:
            ventilation_references = {}

        zones = await self.async_get_zones(device_id)
        zones_references = (zones or {}).get("references", [])
        if zones_references:
            for ref in zones_references:
                zone_id = ref["id"].split("/")[-1]
                ref["temperatureActual"] = await self.async_get_zone_temp_actual(
                    device_id, zone_id
                )
                ref[
                    "manualTemperatureHeating"
                ] = await self.async_get_zone_manual_temp_heating(device_id, zone_id)
        else:
            zones_references = {}

        flame_indication = await self.async_get_hs_flame_indication(device_id)
        heat_sources["flameIndication"] = flame_indication or {}

        energy_history = await self.async_get_energy_history(device_id)
        indoor_humidity = await self.async_get_indoor_humidity(device_id)

        devices = await self.async_get_devices_list(device_id)
        devices_references = (devices or {}).get("references", [])
        if devices_references:
            for ref in devices_references:
                dev_id = ref["id"].split("/")[-1]
                ref["childLock"] = await self.async_get_child_lock(device_id, dev_id)
        else:
            devices_references = {}

        return BHCDeviceK40(
            device=device_id,
            firmware=[],
            notifications=notifications.get("values", []),
            holiday_mode=holiday_mode,
            away_mode=away_mode,
            power_limitation=power_limitation,
            outdoor_temp=outdoor_temp,
            heat_sources=heat_sources,
            dhw_circuits=dhw_circuits["references"],
            heating_circuits=heating_circuits["references"],
            ventilation=ventilation_references,
            zones=zones_references,
            flame_indication=flame_indication,
            energy_history=energy_history,
            indoor_humidity=indoor_humidity,
            devices=devices_references,
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
            notifications=notifications.get("values", []),
            dhw_circuits=dhw_circuits["references"],
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

    async def async_update(self, device_id: str) -> BHCDeviceCommodule:
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        eth0_state = await self.async_get_eth0_state(device_id)
        charge_points_data = await self.async_get_charge_points(device_id)
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
            notifications=notifications.get("values", []),
            charge_points=charge_points_data["references"],
            eth0_state=eth0_state,
        )
