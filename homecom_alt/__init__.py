"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import base64
import hashlib
import logging
import math
import os
import random
import re
from datetime import UTC, datetime
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
    BOSCHCOM_ENDPOINT_CONTROL,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_DWH_CHARGE,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
    BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_ECO,
    BOSCHCOM_ENDPOINT_FAN_SPEED,
    BOSCHCOM_ENDPOINT_FIRMWARE,
    BOSCHCOM_ENDPOINT_FULL_POWER,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY,
    BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
    BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
    BOSCHCOM_ENDPOINT_HC_HEATING_TYPE,
    BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
    BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
    BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
    BOSCHCOM_ENDPOINT_HOLIDAY_MODE,
    BOSCHCOM_ENDPOINT_HS_MODULATION,
    BOSCHCOM_ENDPOINT_HS_PUMP_TYPE,
    BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
    BOSCHCOM_ENDPOINT_HS_STARTS,
    BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
    BOSCHCOM_ENDPOINT_HS_TYPE,
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
    BOSCHCOM_ENDPOINT_TIMER,
    DEFAULT_TIMEOUT,
    JSON,
    OAUTH_BROWSER_VERIFIER,
    OAUTH_DOMAIN,
    OAUTH_ENDPOINT,
    OAUTH_PARAMS,
    OAUTH_REFRESH_PARAMS,
    URLENCODED,
)
from .exceptions import (
    ApiError,
    AuthFailedError,
    InvalidSensorDataError,
    NotRespondingError,
)
from .model import BHCDeviceGeneric, BHCDeviceK40, BHCDeviceRac, ConnectionOptions

_LOGGER = logging.getLogger(__name__)


def get_nonce(length: int) -> str:
    """Generate nonce."""
    possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(
        possible[math.floor(random.uniform(0, 1) * len(possible))]
        for _ in range(length)
    )


def get_oauth_params() -> dict:
    """Generate code challenge and verifier."""
    params = {}
    params["nonce"] = get_nonce(22)
    params["state"] = get_nonce(22)
    code_verifier = (
        base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode("utf-8")
    )
    params["code_verifier"] = code_verifier
    code_challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b"=").decode("utf-8")
    )
    params["code_challenge"] = code_challenge
    return params


def extract_verification_token(page_content: bytes) -> str | Any:
    """Extract the CSRF token from a page."""
    try:
        match = re.search(
            r'<input[^>]*name="__RequestVerificationToken"[^>]*value="([^"]+)"',
            str(page_content),
        )
        if match:
            return match.group(1)
        raise ApiError("Invalid response in auth")
    except re.PatternError as err:
        raise ApiError(f"Invalid response in auth {err}") from err


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
            if error.status == HTTPStatus.NOT_FOUND.value:
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
        """Get switch."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_TIME,
        )
        return await self._to_data(response)

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
            return datetime.now(UTC) < datetime.fromtimestamp(exp, UTC)
        except jwt.DecodeError as err:
            _LOGGER.error("Invalid token: %s", err)
            return False

    async def get_token(self) -> bool | None:
        """Retrieve a new token using the refresh token."""
        if self._auth_provider:
            if self.check_jwt():
                return None
            if self._options.refresh_token:
                data = OAUTH_REFRESH_PARAMS
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
            + urlencode(OAUTH_PARAMS)
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

        notifications = await self.async_get_notifications(device_id)
        return BHCDeviceGeneric(
            device=device_id,
            firmware=[],
            notifications=notifications.get("values", []),
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

    async def async_update(self, device_id: str) -> BHCDeviceK40:
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        dhw_circuits = await self.async_get_dhw(device_id)
        references = dhw_circuits.get("references", [])
        if not references:
            raise InvalidSensorDataError("No DHW circuits found")
        for ref in references:
            dhw_id = ref["id"].split("/")[-1]
            ref["operationMode"] = await self.async_get_dhw_operation_mode(
                device_id, dhw_id
            )
            ref["actualTemp"] = await self.async_get_dhw_actual_temp(device_id, dhw_id)
            ref["charge"] = await self.async_get_dhw_charge(device_id, dhw_id)
            ref["chargeRemainingTime"] = await self.async_get_dhw_charge_remaining_time(
                device_id, dhw_id
            )
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

        heating_circuits = await self.async_get_hc(device_id)
        references = heating_circuits.get("references", [])
        if not references:
            raise InvalidSensorDataError("No HC circuits found")
        for ref in references:
            hc_id = ref["id"].split("/")[-1]
            ref["operationMode"] = await self.async_get_hc_operation_mode(
                device_id, hc_id
            )
            ref["currentSuWiMode"] = await self.async_get_hc_suwi_mode(device_id, hc_id)
            ref["heatCoolMode"] = await self.async_get_hc_heatcool_mode(
                device_id, hc_id
            )
            ref["roomTemp"] = await self.async_get_hc_room_temp(device_id, hc_id)
            ref["actualHumidity"] = await self.async_get_hc_actual_humidity(
                device_id, hc_id
            )
            ref["manualRoomSetpoint"] = await self.async_get_hc_manual_room_setpoint(
                device_id, hc_id
            )
            ref["currentRoomSetpoint"] = await self.async_get_hc_current_room_setpoint(
                device_id, hc_id
            )
            ref[
                "coolingRoomTempSetpoint"
            ] = await self.async_get_hc_cooling_room_temp_setpoint(device_id, hc_id)

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

        heat_sources["consumption"] = (
            await self.async_get_hs_total_consumption(device_id) or {}
        )

        holiday_mode = await self.async_get_holiday_mode(device_id)
        away_mode = await self.async_get_away_mode(device_id)
        power_limitation = await self.async_get_power_limitation(device_id)
        outdoor_temp = await self.async_get_outdoor_temp(device_id)

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
        )
