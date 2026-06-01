"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_ADVANCED,
    BOSCHCOM_ENDPOINT_AIRFLOW_HORIZONTAL,
    BOSCHCOM_ENDPOINT_AIRFLOW_VERTICAL,
    BOSCHCOM_ENDPOINT_CONTROL,
    BOSCHCOM_ENDPOINT_ECO,
    BOSCHCOM_ENDPOINT_FAN_SPEED,
    BOSCHCOM_ENDPOINT_FULL_POWER,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_MODE,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_PLASMACLUSTER,
    BOSCHCOM_ENDPOINT_STANDARD,
    BOSCHCOM_ENDPOINT_SWITCH,
    BOSCHCOM_ENDPOINT_SWITCH_ENABLE,
    BOSCHCOM_ENDPOINT_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_TEMP,
    BOSCHCOM_ENDPOINT_TIMER,
)
from .model import (
    BHCDeviceRac,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


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
