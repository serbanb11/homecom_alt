"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW,
    BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION,
    BOSCHCOM_ENDPOINT_DWH_HOT_WATER_SYSTEM,
    BOSCHCOM_ENDPOINT_DWH_STATE,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_LAST_RESULT,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_OPERATING_SEASON,
    BOSCHCOM_ENDPOINT_HC_TYPE,
    BOSCHCOM_ENDPOINT_HC_TYPE_ROOM_CONTROL,
    BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
    BOSCHCOM_ENDPOINT_HS_INFO,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_WIFI_RSSI,
    BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION,
    BOSCHCOM_ENDPOINT_ZONE_ICON,
    BOSCHCOM_ENDPOINT_ZONE_NAME,
    BOSCHCOM_ENDPOINT_ZONES,
    MAX_CONCURRENT,
)
from .k40 import HomeComK40
from .model import (
    BHCDeviceRrc2,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


class HomeComRrc2(HomeComK40):
    """HomeCom client for rrc2 (Remeha Remote Control) gateways.

    The gateway serves K40-style /zones, /heatingCircuits, /dhwCircuits paths
    but with a trimmed and slightly different field set (per issue #78 dumps).
    Inherits K40 GET/SET methods that work on RRC2 (zone setpoint, HC curve,
    away mode, child lock, heat sources) and adds DHW thermal-disinfect /
    extra-DHW / hot-water-system and the RRC2-only gateway endpoints.
    """

    def __init__(
        self,
        session: ClientSession,
        options: Any,
        device_id: str,
        auth_provider: bool,
    ) -> None:
        """Initialize Rrc2 device."""
        HomeComAlt.__init__(self, session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "rrc2"

    async def _async_get_zone_field(
        self, device_id: str, zone_id: str, suffix: str
    ) -> Any:
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ZONES
            + "/"
            + zone_id
            + suffix,
        )
        return await self._to_data(response)

    async def async_get_zone_name(self, device_id: str, zone_id: str) -> Any:
        """Zone name."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_ZONE_NAME
        )

    async def async_get_zone_icon(self, device_id: str, zone_id: str) -> Any:
        """Zone icon identifier."""
        return await self._async_get_zone_field(
            device_id, zone_id, BOSCHCOM_ENDPOINT_ZONE_ICON
        )

    async def _async_get_hc_subresource(
        self, device_id: str, hc_id: str, suffix: str
    ) -> Any:
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

    async def async_get_hc_operating_season(self, device_id: str, hc_id: str) -> Any:
        """Heating circuit current operating season."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_OPERATING_SEASON
        )

    async def async_get_hc_type(self, device_id: str, hc_id: str) -> Any:
        """Heating circuit type."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TYPE
        )

    async def async_get_hc_type_room_control(self, device_id: str, hc_id: str) -> Any:
        """Heating circuit room control type."""
        return await self._async_get_hc_subresource(
            device_id, hc_id, BOSCHCOM_ENDPOINT_HC_TYPE_ROOM_CONTROL
        )

    async def _async_dhw_field(
        self,
        device_id: str,
        dhw_id: str,
        suffix: str,
    ) -> Any:
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + suffix,
        )
        return await self._to_data(response)

    async def _async_set_dhw_field(
        self,
        device_id: str,
        dhw_id: str,
        suffix: str,
        value: Any,
    ) -> None:
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + suffix,
            {"value": value},
            1,
        )

    async def async_get_dhw_hot_water_system(self, device_id: str, dhw_id: str) -> Any:
        """DHW hot water system kind (e.g. instant, tank)."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_HOT_WATER_SYSTEM
        )

    async def async_get_dhw_state(self, device_id: str, dhw_id: str) -> Any:
        """DHW state."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_STATE
        )

    async def async_get_dhw_extra_dhw(self, device_id: str, dhw_id: str) -> Any:
        """DHW extra-DHW boost flag."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW
        )

    async def async_set_dhw_extra_dhw(
        self, device_id: str, dhw_id: str, value: str
    ) -> None:
        """Toggle DHW extra-DHW boost."""
        await self._async_set_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW, value
        )

    async def async_get_dhw_extra_dhw_duration(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """DHW extra-DHW duration (minutes)."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION
        )

    async def async_set_dhw_extra_dhw_duration(
        self, device_id: str, dhw_id: str, minutes: int
    ) -> None:
        """Set DHW extra-DHW duration (minutes, 15..2880 step 15)."""
        await self._async_set_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION, minutes
        )

    async def async_get_dhw_temp_level_high(self, device_id: str, dhw_id: str) -> Any:
        """DHW high temperature level (°C)."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH
        )

    async def async_set_dhw_temp_level_high(
        self, device_id: str, dhw_id: str, temp: float
    ) -> None:
        """Set DHW high temperature level (°C, 10..80)."""
        await self._async_set_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH, temp
        )

    async def async_get_dhw_thermal_disinfect_state(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """DHW thermal-disinfect program state."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE
        )

    async def async_set_dhw_thermal_disinfect_state(
        self, device_id: str, dhw_id: str, value: str
    ) -> None:
        """Enable/disable DHW thermal disinfect."""
        await self._async_set_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE, value
        )

    async def async_get_dhw_thermal_disinfect_time(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """DHW thermal disinfect minute-of-day."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME
        )

    async def async_set_dhw_thermal_disinfect_time(
        self, device_id: str, dhw_id: str, minutes: int
    ) -> None:
        """Set DHW thermal disinfect minute-of-day (0..1439)."""
        await self._async_set_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME, minutes
        )

    async def async_get_dhw_thermal_disinfect_weekday(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """DHW thermal disinfect day of week."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY
        )

    async def async_set_dhw_thermal_disinfect_weekday(
        self, device_id: str, dhw_id: str, weekday: str
    ) -> None:
        """Set DHW thermal disinfect day of week (Mo|Tu|We|Th|Fr|Sa|Su)."""
        await self._async_set_dhw_field(
            device_id,
            dhw_id,
            BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY,
            weekday,
        )

    async def async_get_dhw_thermal_disinfect_last_result(
        self, device_id: str, dhw_id: str
    ) -> Any:
        """DHW thermal disinfect last result."""
        return await self._async_dhw_field(
            device_id, dhw_id, BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_LAST_RESULT
        )

    async def async_get_heat_sources_info(self, device_id: str) -> Any:
        """Get the /heatSources/info payload."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_HS_INFO,
        )
        return await self._to_data(response)

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

    async def async_get_gateway_wifi_rssi(self, device_id: str) -> Any:
        """Gateway WiFi RSSI (dBm)."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_RRC2_GATEWAY_WIFI_RSSI,
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

    async def async_update(  # type: ignore[override]
        self, device_id: str
    ) -> BHCDeviceRrc2:
        """Fetch the rrc2-supported endpoint set and return a BHCDeviceRrc2."""
        await self.get_token()

        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def limited_call(coro: Any) -> Any:
            async with sem:
                return await coro

        firmware = await self.async_get_firmware(device_id)

        (
            notifications,
            zones,
            heating_circuits,
            dhw_circuits,
            devices,
            away_mode,
            outdoor_temp,
            indoor_humidity,
            hs_type,
            hs_info,
            hs_flame,
            hs_supply,
            hs_return,
            hs_modulation,
            hs_working_time,
            hs_starts,
            gw_uuid,
            gw_time,
            gw_timezone,
            gw_rssi,
            system_location,
        ) = await asyncio.gather(
            limited_call(self.async_get_notifications(device_id)),
            limited_call(self.async_get_zones(device_id)),
            limited_call(self.async_get_hc(device_id)),
            limited_call(self.async_get_dhw(device_id)),
            limited_call(self.async_get_devices_list(device_id)),
            limited_call(self.async_get_away_mode(device_id)),
            limited_call(self.async_get_outdoor_temp(device_id)),
            limited_call(self.async_get_indoor_humidity(device_id)),
            limited_call(self.async_get_hs_type(device_id)),
            limited_call(self.async_get_heat_sources_info(device_id)),
            limited_call(self.async_get_hs_flame_indication(device_id)),
            limited_call(self.async_get_hs_supply_temp(device_id)),
            limited_call(self.async_get_hs_return_temp(device_id)),
            limited_call(self.async_get_hs_modulation(device_id)),
            limited_call(self.async_get_hs_working_time(device_id)),
            limited_call(self.async_get_hs_starts(device_id)),
            limited_call(self.async_get_gateway_uuid(device_id)),
            limited_call(self.async_get_gateway_time(device_id)),
            limited_call(self.async_get_gateway_timezone(device_id)),
            limited_call(self.async_get_gateway_wifi_rssi(device_id)),
            limited_call(self.async_get_system_location(device_id)),
        )

        zones = zones or {}
        zone_refs = zones.get("references", [])
        if zone_refs:

            async def populate_zone(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                (
                    ref["temperatureActual"],
                    ref["temperatureHeatingSetpoint"],
                    ref["manualTemperatureHeating"],
                    ref["userMode"],
                    ref["name"],
                    ref["icon"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_zone_temp_actual(device_id, zone_id)),
                    limited_call(self.async_get_zone_temp_setpoint(device_id, zone_id)),
                    limited_call(
                        self.async_get_zone_manual_temp_heating(device_id, zone_id)
                    ),
                    limited_call(self.async_get_zone_user_mode(device_id, zone_id)),
                    limited_call(self.async_get_zone_name(device_id, zone_id)),
                    limited_call(self.async_get_zone_icon(device_id, zone_id)),
                )

            await asyncio.gather(*(populate_zone(ref) for ref in zone_refs))

        heating_circuits = heating_circuits or {}
        hc_refs = heating_circuits.get("references", [])
        if hc_refs:

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                (
                    ref["supplyTemperatureSetpoint"],
                    ref["operatingSeason"],
                    ref["type"],
                    ref["typeRoomControl"],
                    ref["maxSupply"],
                    ref["minSupply"],
                    ref["heatCurveMax"],
                    ref["heatCurveMin"],
                    ref["nightSwitchMode"],
                    ref["nightThreshold"],
                    ref["roomInfluence"],
                    ref["control"],
                ) = await asyncio.gather(
                    limited_call(
                        self.async_get_hc_supply_temp_setpoint(device_id, hc_id)
                    ),
                    limited_call(self.async_get_hc_operating_season(device_id, hc_id)),
                    limited_call(self.async_get_hc_type(device_id, hc_id)),
                    limited_call(self.async_get_hc_type_room_control(device_id, hc_id)),
                    limited_call(self.async_get_hc_max_supply(device_id, hc_id)),
                    limited_call(self.async_get_hc_min_supply(device_id, hc_id)),
                    limited_call(self.async_get_hc_heat_curve_max(device_id, hc_id)),
                    limited_call(self.async_get_hc_heat_curve_min(device_id, hc_id)),
                    limited_call(self.async_get_hc_night_switch_mode(device_id, hc_id)),
                    limited_call(self.async_get_hc_night_threshold(device_id, hc_id)),
                    limited_call(self.async_get_hc_room_influence(device_id, hc_id)),
                    limited_call(self.async_get_hc_control(device_id, hc_id)),
                )

            await asyncio.gather(*(populate_hc(ref) for ref in hc_refs))

        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                (
                    ref["actualTemp"],
                    ref["state"],
                    ref["hotWaterSystem"],
                    ref["operationMode"],
                    ref["extraDhw"],
                    ref["extraDhwDuration"],
                    ref["temperatureLevelHigh"],
                    ref["thermalDisinfectState"],
                    ref["thermalDisinfectTime"],
                    ref["thermalDisinfectWeekDay"],
                    ref["thermalDisinfectLastResult"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_dhw_actual_temp(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_state(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_hot_water_system(device_id, dhw_id)
                    ),
                    limited_call(self.async_get_dhw_operation_mode(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_extra_dhw(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_extra_dhw_duration(device_id, dhw_id)
                    ),
                    limited_call(self.async_get_dhw_temp_level_high(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_thermal_disinfect_state(device_id, dhw_id)
                    ),
                    limited_call(
                        self.async_get_dhw_thermal_disinfect_time(device_id, dhw_id)
                    ),
                    limited_call(
                        self.async_get_dhw_thermal_disinfect_weekday(device_id, dhw_id)
                    ),
                    limited_call(
                        self.async_get_dhw_thermal_disinfect_last_result(
                            device_id, dhw_id
                        )
                    ),
                )

            await asyncio.gather(*(populate_dhw(ref) for ref in dhw_refs))

        devices = devices or {}
        device_refs = devices.get("references", [])
        if device_refs:

            async def populate_device(ref: dict[str, Any]) -> None:
                dev_id = ref["id"].split("/")[-1]
                (
                    ref["type"],
                    ref["childLockEnabled"],
                    ref["roomtemperature"],
                    ref["actualHumidity"],
                    ref["signal"],
                    ref["battery"],
                    ref["currentRoomSetpoint"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_device_type(device_id, dev_id)),
                    limited_call(self.async_get_child_lock(device_id, dev_id)),
                    limited_call(self.async_get_device_room_temp(device_id, dev_id)),
                    limited_call(self.async_get_device_humidity(device_id, dev_id)),
                    limited_call(self.async_get_device_signal(device_id, dev_id)),
                    limited_call(self.async_get_device_battery(device_id, dev_id)),
                    limited_call(
                        self.async_get_device_current_room_setpoint(device_id, dev_id)
                    ),
                )

            await asyncio.gather(*(populate_device(ref) for ref in device_refs))

        heat_sources = {
            "type": hs_type or {},
            "info": hs_info or {},
            "flameIndication": hs_flame or {},
            "supplyTemperature": hs_supply or {},
            "returnTemperature": hs_return or {},
            "modulation": hs_modulation or {},
            "workingTime": hs_working_time or {},
            "numberOfStarts": hs_starts or {},
        }

        gateway_info = {
            "uuid": gw_uuid or {},
            "time": gw_time or {},
            "timezone": gw_timezone or {},
            "wifiRssi": gw_rssi or {},
        }

        return BHCDeviceRrc2(
            device=device_id,
            firmware=firmware,
            notifications=(notifications or {}).get("values") or [],
            zones=zone_refs,
            heating_circuits=hc_refs,
            dhw_circuits=dhw_refs,
            heat_sources=heat_sources,
            away_mode=away_mode or {},
            outdoor_temp=outdoor_temp or {},
            indoor_humidity=indoor_humidity or {},
            devices=device_refs,
            gateway_info=gateway_info,
            system_location=system_location or {},
        )
