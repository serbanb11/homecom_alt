"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_AWAY_MODE,
    BOSCHCOM_ENDPOINT_BULK,
    BOSCHCOM_ENDPOINT_CHILD_LOCK,
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
    BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_DWH_CHARGE,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
    BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_ENERGY_GAS_UNIT,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY_ENTRIES,
    BOSCHCOM_ENDPOINT_ENERGY_HISTORY_HOURLY,
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
    BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT,
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
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
    BOSCHCOM_ENDPOINT_POWER_LIMITATION,
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
    BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
    BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
    BOSCHCOM_ENDPOINT_ZONES,
    MAX_CONCURRENT,
)
from .model import (
    BHCDeviceK40,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


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

    async def async_set_hc_temporary_room_setpoint(
        self, device_id: str, hc_id: str, temp: float
    ) -> None:
        """Set a temporary room-temperature override for a heating circuit."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HEATING_CIRCUITS
            + "/"
            + hc_id
            + BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT,
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

    async def async_set_dhw_charge_setpoint(
        self, device_id: str, dhw_id: str, temp: float
    ) -> None:
        """Set dhw singleChargeSetpoint (°C, typically 50..70)."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
            {"value": temp},
            1,
        )

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

        # Fetch core resource endpoints + heat source sensors in a single bulk request
        bulk_endpoints = [
            BOSCHCOM_ENDPOINT_NOTIFICATIONS,
            BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
            BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
            BOSCHCOM_ENDPOINT_HOLIDAY_MODE,
            BOSCHCOM_ENDPOINT_AWAY_MODE,
            BOSCHCOM_ENDPOINT_POWER_LIMITATION,
            BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
            BOSCHCOM_ENDPOINT_VENTILATION,
            BOSCHCOM_ENDPOINT_ZONES,
            BOSCHCOM_ENDPOINT_HS_FLAME,
            BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY,
            BOSCHCOM_ENDPOINT_DEVICES,
            # Heat source sensors
            BOSCHCOM_ENDPOINT_HS_PUMP_TYPE,
            BOSCHCOM_ENDPOINT_HS_STARTS,
            BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
            BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
            BOSCHCOM_ENDPOINT_HS_MODULATION,
            BOSCHCOM_ENDPOINT_HS_INFLOW_TEMP,
            BOSCHCOM_ENDPOINT_HS_OUTFLOW_TEMP,
            BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND,
            BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
            BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
            BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE,
        ]
        bulk_response = await self.async_request_bulk(device_id, bulk_endpoints) or {}

        notifications = bulk_response.get(BOSCHCOM_ENDPOINT_NOTIFICATIONS)
        dhw_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_DHW_CIRCUITS)
        heating_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_HEATING_CIRCUITS)
        holiday_mode = bulk_response.get(BOSCHCOM_ENDPOINT_HOLIDAY_MODE)
        away_mode = bulk_response.get(BOSCHCOM_ENDPOINT_AWAY_MODE)
        power_limitation = bulk_response.get(BOSCHCOM_ENDPOINT_POWER_LIMITATION)
        outdoor_temp = bulk_response.get(BOSCHCOM_ENDPOINT_OUTDOOR_TEMP)
        ventilation = bulk_response.get(BOSCHCOM_ENDPOINT_VENTILATION)
        zones = bulk_response.get(BOSCHCOM_ENDPOINT_ZONES)
        if zones and "references" in zones:
            zones["references"] = [
                ref
                for ref in zones["references"]
                if ref.get("id") not in ("/zones/deviceTypeAllowed", "/zones/list")
            ]
        flame_indication = bulk_response.get(BOSCHCOM_ENDPOINT_HS_FLAME)
        indoor_humidity = bulk_response.get(BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY)
        devices = bulk_response.get(BOSCHCOM_ENDPOINT_DEVICES)

        heat_sources = {
            "pumpType": bulk_response.get(BOSCHCOM_ENDPOINT_HS_PUMP_TYPE) or {},
            "starts": bulk_response.get(BOSCHCOM_ENDPOINT_HS_STARTS) or {},
            "returnTemperature": bulk_response.get(BOSCHCOM_ENDPOINT_HS_RETURN_TEMP)
            or {},
            "actualSupplyTemperature": bulk_response.get(
                BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP
            )
            or {},
            "actualModulation": bulk_response.get(BOSCHCOM_ENDPOINT_HS_MODULATION)
            or {},
            "collectorInflowTemp": bulk_response.get(BOSCHCOM_ENDPOINT_HS_INFLOW_TEMP)
            or {},
            "collectorOutflowTemp": bulk_response.get(BOSCHCOM_ENDPOINT_HS_OUTFLOW_TEMP)
            or {},
            "actualHeatDemand": bulk_response.get(BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND)
            or {},
            "totalWorkingTime": bulk_response.get(BOSCHCOM_ENDPOINT_HS_WORKING_TIME)
            or {},
            "consumption": bulk_response.get(BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION)
            or {},
            "systemPressure": bulk_response.get(BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE)
            or {},
            "flameIndication": flame_indication or {},
        }

        # Energy endpoints fetched individually
        (
            energy_history,
            hourly_energy_history,
            energy_gas_unit,
        ) = await asyncio.gather(
            limited_call(self.async_get_energy_history(device_id)),
            limited_call(self.async_get_energy_history_hourly(device_id)),
            limited_call(self.async_get_energy_gas_unit(device_id)),
        )

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
                prefix = BOSCHCOM_ENDPOINT_HEATING_CIRCUITS + "/" + hc_id
                hc_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY,
                    prefix + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
                    prefix + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
                    prefix + BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_CONTROL,
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
                ]
                hc_bulk = await self.async_request_bulk(device_id, hc_endpoints) or {}
                ref["operationMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE
                )
                ref["currentSuWiMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_MODE
                )
                ref["heatCoolMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE
                )
                ref["roomTemp"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_ROOM_TEMP)
                ref["actualHumidity"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY
                )
                ref["manualRoomSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT
                )
                ref["currentRoomSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT
                )
                ref["coolingRoomTempSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT
                )
                ref["maxSupply"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY)
                ref["minSupply"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY)
                ref["heatCurveMax"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX
                )
                ref["heatCurveMin"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN
                )
                ref["supplyTemperatureSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT
                )
                ref["nightSwitchMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE
                )
                ref["control"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_CONTROL)
                ref["nightThreshold"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD
                )
                ref["roomInfluence"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE
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
                prefix = BOSCHCOM_ENDPOINT_VENTILATION + "/" + zone_id
                vent_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_FAN,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_QUALITY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_HUMIDITY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_EXHAUST_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_EXTRACT_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_QUALITY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_HUMIDITY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OUTDOOR_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_FLAP_POWER,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_MIN_SUPPLY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_PASSIVE_COOLING,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY,
                ]
                vent_bulk = (
                    await self.async_request_bulk(device_id, vent_endpoints) or {}
                )
                ref["exhaustFanLevel"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_FAN
                )
                ref["maxIndoorAirQuality"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_QUALITY
                )
                ref["maxRelativeHumidity"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_HUMIDITY
                )
                ref["operationMode"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE
                )
                ref["exhaustTemp"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_EXHAUST_TEMP
                )
                ref["extractTemp"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_EXTRACT_TEMP
                )
                ref["internalAirQuality"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_QUALITY
                )
                ref["internalHumidity"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_HUMIDITY
                )
                ref["outdoorTemp"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OUTDOOR_TEMP
                )
                ref["supplyTemp"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP
                )
                ref["summerBypassEnable"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE
                )
                ref["summerBypassDuration"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION
                )
                ref["summerBypassFlapPower"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_FLAP_POWER
                )
                ref["summerBypassMinSupply"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_MIN_SUPPLY
                )
                ref["summerBypassPassiveCooling"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_PASSIVE_COOLING
                )
                ref["demandindoorAirQuality"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY
                )
                ref["demandrelativeHumidity"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY
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
