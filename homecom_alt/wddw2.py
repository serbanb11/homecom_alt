"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DWH_AIRBOX,
    BOSCHCOM_ENDPOINT_DWH_FAN_SPEED,
    BOSCHCOM_ENDPOINT_DWH_INLET_TEMP,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_OUTLET_TEMP,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_MANUAL,
    BOSCHCOM_ENDPOINT_DWH_WATER_FLOW,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HS_STARTS,
)
from .model import (
    BHCDeviceWddw2,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


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
        # Top-level totals and heat-source telemetry (issue #129).
        water_total = await self.async_get_dhw_water_total_consumption(device_id)
        hs_actual_power = await self.async_get_hs_actual_power(device_id)
        hs_power_percentage = await self.async_get_hs_power_percentage(device_id)
        hs_operation_hours = await self.async_get_hs_operation_hours(device_id)
        hs_electricity_total = await self.async_get_hs_electricity_total_consumption(
            device_id
        )
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
            heat_sources={
                "actualPower": hs_actual_power or {},
                "powerPercentage": hs_power_percentage or {},
                "operationHours": hs_operation_hours or {},
                "electricityTotalConsumption": hs_electricity_total or {},
            },
            water_total_consumption=water_total or {},
        )
