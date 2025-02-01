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
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from aiohttp import (
    ClientConnectorError,
    ClientResponse,
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
    BOSCHCOM_ENDPOINT_CONTROL,
    BOSCHCOM_ENDPOINT_ECO,
    BOSCHCOM_ENDPOINT_FAN_SPEED,
    BOSCHCOM_ENDPOINT_FIRMWARE,
    BOSCHCOM_ENDPOINT_FULL_POWER,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_MODE,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_PLASMACLUSTER,
    BOSCHCOM_ENDPOINT_PV_LIST,
    BOSCHCOM_ENDPOINT_STANDARD,
    BOSCHCOM_ENDPOINT_SWITCH,
    BOSCHCOM_ENDPOINT_SWITCH_ENABLE,
    BOSCHCOM_ENDPOINT_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_TEMP,
    BOSCHCOM_ENDPOINT_TIME,
    BOSCHCOM_ENDPOINT_TIMER,
    DEFAULT_TIMEOUT,
    JSON,
    OAUTH_DOMAIN,
    OAUTH_ENDPOINT,
    OAUTH_LOGIN,
    OAUTH_LOGIN_PARAMS,
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
from .model import BHCDevice, ConnectionOptions

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

    def __init__(self, session: ClientSession, options: ConnectionOptions) -> None:
        """Initialize."""
        self._options = options
        self._session = session
        self._count = 0
        self._update_errors: int = 0

    @classmethod
    async def create(
        cls, session: ClientSession, options: ConnectionOptions
    ) -> HomeComAlt:
        """Create a new device instance."""
        instance = cls(session, options)
        await instance.initialize()
        return instance

    async def initialize(self) -> None:
        """Initialize."""
        _LOGGER.debug("Initializing device")

        try:
            await self.get_token()
        except AuthFailedError as error:
            raise AuthFailedError("Authorization has failed") from error

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
            raise ApiError(
                f"Invalid response from url {url}: {error.status}"
            ) from error
        except (TimeoutError, ClientConnectorError) as error:
            raise NotRespondingError(f"{url} is not responding") from error

        _LOGGER.debug("Data retrieved from %s, status: %s", url, resp.status)
        if resp.status not in {HTTPStatus.OK.value, HTTPStatus.NO_CONTENT.value}:
            raise ApiError(f"Invalid response from {url}: {resp.status}")

        return resp

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
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_notifications(self, device_id: str) -> Any:
        """Get notifications."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_NOTIFICATIONS,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_stardard(self, device_id: str) -> Any:
        """Get get standard functions."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_STANDARD,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_advanced(self, device_id: str) -> Any:
        """Get advanced functions."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ADVANCED,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_switch(self, device_id: str) -> Any:
        """Get switch."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_SWITCH,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_time(self, device_id: str) -> Any:
        """Get switch."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_TIME,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_get_pv_list(self, device_id: str) -> Any:
        """Get pv list."""
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_PV_LIST,
        )
        try:
            return await response.json()
        except ValueError as error:
            raise InvalidSensorDataError("Invalid devices data") from error

    async def async_update(self, device_id: str) -> BHCDevice:
        """Retrieve data from the device."""
        await self.get_token()
        if self._count == 0:
            firmware = await self.async_get_firmware(device_id)
            firmware = firmware.get("value", [])
            notifications = await self.async_get_notifications(device_id)
            notifications = notifications.get("value", [])
        else:
            firmware = {}
            notifications = {}
        self._count = (self._count + 1) % 72
        stardard_functions = await self.async_get_stardard(device_id)
        advanced_functions = await self.async_get_advanced(device_id)
        switch_programs = await self.async_get_switch(device_id)
        return BHCDevice(
            device=device_id,
            firmware=firmware,
            notifications=notifications,
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

        response = await self.do_auth()
        if response:
            self._options.token = response["access_token"]
            self._options.refresh_token = response["refresh_token"]
            return True

        _LOGGER.error("Failed to refresh or reauthenticate")
        return False

    async def do_auth_step1(self, params: dict) -> tuple[str, str]:
        """GET CSRF token from singlekey-id."""
        response = await self._async_http_request(
            "get",
            OAUTH_DOMAIN
            + OAUTH_LOGIN
            + "?"
            + urlencode(params)
            + "&"
            + urlencode(OAUTH_LOGIN_PARAMS),
        )
        return str(response.url), extract_verification_token(await response.text())

    async def do_auth_step2(self, url: str, csrf_token: str) -> tuple[str, str]:
        """POST username from singlekey-id."""
        user_payload = {
            "UserIdentifierInput.EmailInput.StringValue": self._options.username,
            "__RequestVerificationToken": csrf_token,
        }
        """Get firmware."""
        response = await self._async_http_request("post", str(url), data=user_payload)
        return str(response.url), extract_verification_token(await response.text())

    async def do_auth_step3(self, url: str, csrf_token: str) -> ClientResponse:
        """POST password from singlekey-id."""
        # POST password
        pass_payload = {
            "Password": self._options.password,
            "__RequestVerificationToken": csrf_token,
        }
        """Get firmware."""
        try:
            return await self._session.post(
                str(url),
                data=pass_payload,
                allow_redirects=False,
            )
        except ClientResponseError as error:
            raise AuthFailedError("Authorization has failed") from error
        except (TimeoutError, ClientConnectorError) as error:
            raise NotRespondingError("Oauth endpoint is not responding") from error

    async def do_auth(self) -> dict[Any, Any] | None:
        """Singlekey-id login - get code."""
        self._session.cookie_jar.clear_domain(OAUTH_DOMAIN[8:])

        params = get_oauth_params()

        response_url, csrf_token = await self.do_auth_step1(
            {key: params[key] for key in ["state", "nonce", "code_challenge"]}
        )

        response_url, csrf_token = await self.do_auth_step2(
            str(response_url), str(csrf_token)
        )

        response = await self.do_auth_step3(str(response_url), str(csrf_token))

        """Get firmware."""
        try:
            # First redirect
            if response.headers.get("Location") is not None:
                location: str = str(response.headers.get("Location"))
                async with self._session.get(
                    response.url.scheme + "://" + response.host + location,
                    allow_redirects=False,
                ) as respose:
                    # Get and parse the Location header from the response
                    location_query_params = parse_qs(
                        urlparse(respose.headers.get("Location", "")).query
                    )
                    code = location_query_params.get("code", [None])[0]
            else:
                raise AuthFailedError("Authorization has failed")
        except ClientResponseError as error:
            raise AuthFailedError("Authorization has failed") from error
        except (TimeoutError, ClientConnectorError) as error:
            raise NotRespondingError("Oauth endpoint is not responding") from error

        # get token
        if code:
            return await self.validate_auth(code, params["code_verifier"])
        raise AuthFailedError("Authorization has failed")

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
