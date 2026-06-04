"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_AWAY_MODE,
    BOSCHCOM_ENDPOINT_CHILD_LOCK,
    BOSCHCOM_ENDPOINT_DEVICE_BATTERY,
    BOSCHCOM_ENDPOINT_DEVICE_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_DEVICE_HUMIDITY,
    BOSCHCOM_ENDPOINT_DEVICE_ROOM_TEMP,
    BOSCHCOM_ENDPOINT_DEVICE_SIGNAL,
    BOSCHCOM_ENDPOINT_DEVICE_TYPE,
    BOSCHCOM_ENDPOINT_DEVICES,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW,
    BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION,
    BOSCHCOM_ENDPOINT_DWH_HOT_WATER_SYSTEM,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_STATE,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_LAST_RESULT,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME,
    BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_CONTROL,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
    BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
    BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
    BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
    BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
    BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
    BOSCHCOM_ENDPOINT_HC_OPERATING_SEASON,
    BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
    BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_TYPE,
    BOSCHCOM_ENDPOINT_HC_TYPE_ROOM_CONTROL,
    BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
    BOSCHCOM_ENDPOINT_HS_FLAME,
    BOSCHCOM_ENDPOINT_HS_INFO,
    BOSCHCOM_ENDPOINT_HS_MODULATION,
    BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
    BOSCHCOM_ENDPOINT_HS_STARTS,
    BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_HS_TYPE,
    BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
    BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID,
    BOSCHCOM_ENDPOINT_RRC2_GATEWAY_WIFI_RSSI,
    BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION,
    BOSCHCOM_ENDPOINT_ZONE_ICON,
    BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_NAME,
    BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING,
    BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
    BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
    BOSCHCOM_ENDPOINT_ZONES,
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

    async def async_update(  # type: ignore[override]  # noqa: PLR0915
        self, device_id: str
    ) -> BHCDeviceRrc2:
        """Fetch the rrc2-supported endpoint set and return a BHCDeviceRrc2."""
        await self.get_token()

        firmware = await self.async_get_firmware(device_id)

        # --- Static endpoints: single bulk call ---
        bulk_endpoints = [
            BOSCHCOM_ENDPOINT_NOTIFICATIONS,
            BOSCHCOM_ENDPOINT_ZONES,
            BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
            BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
            BOSCHCOM_ENDPOINT_DEVICES,
            BOSCHCOM_ENDPOINT_AWAY_MODE,
            BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
            BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY,
            BOSCHCOM_ENDPOINT_HS_TYPE,
            BOSCHCOM_ENDPOINT_HS_INFO,
            BOSCHCOM_ENDPOINT_HS_FLAME,
            BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
            BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
            BOSCHCOM_ENDPOINT_HS_MODULATION,
            BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
            BOSCHCOM_ENDPOINT_HS_STARTS,
            BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID,
            BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME,
            BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE,
            BOSCHCOM_ENDPOINT_RRC2_GATEWAY_WIFI_RSSI,
            BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION,
        ]
        bulk_response = await self.async_request_bulk(device_id, bulk_endpoints) or {}

        notifications = bulk_response.get(BOSCHCOM_ENDPOINT_NOTIFICATIONS)
        zones = bulk_response.get(BOSCHCOM_ENDPOINT_ZONES)
        heating_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_HEATING_CIRCUITS)
        dhw_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_DHW_CIRCUITS)
        devices = bulk_response.get(BOSCHCOM_ENDPOINT_DEVICES)
        away_mode = bulk_response.get(BOSCHCOM_ENDPOINT_AWAY_MODE)
        outdoor_temp = bulk_response.get(BOSCHCOM_ENDPOINT_OUTDOOR_TEMP)
        indoor_humidity = bulk_response.get(BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY)
        hs_type = bulk_response.get(BOSCHCOM_ENDPOINT_HS_TYPE)
        hs_info = bulk_response.get(BOSCHCOM_ENDPOINT_HS_INFO)
        hs_flame = bulk_response.get(BOSCHCOM_ENDPOINT_HS_FLAME)
        hs_supply = bulk_response.get(BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP)
        hs_return = bulk_response.get(BOSCHCOM_ENDPOINT_HS_RETURN_TEMP)
        hs_modulation = bulk_response.get(BOSCHCOM_ENDPOINT_HS_MODULATION)
        hs_working_time = bulk_response.get(BOSCHCOM_ENDPOINT_HS_WORKING_TIME)
        hs_starts = bulk_response.get(BOSCHCOM_ENDPOINT_HS_STARTS)
        gw_uuid = bulk_response.get(BOSCHCOM_ENDPOINT_RRC2_GATEWAY_UUID)
        gw_time = bulk_response.get(BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIME)
        gw_timezone = bulk_response.get(BOSCHCOM_ENDPOINT_RRC2_GATEWAY_TIMEZONE)
        gw_rssi = bulk_response.get(BOSCHCOM_ENDPOINT_RRC2_GATEWAY_WIFI_RSSI)
        system_location = bulk_response.get(BOSCHCOM_ENDPOINT_RRC2_SYSTEM_LOCATION)

        # --- Per-zone bulk ---
        zones = zones or {}
        zone_refs = zones.get("references", [])
        if zone_refs:

            async def populate_zone(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_ZONES + "/" + zone_id
                zone_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL,
                    prefix + BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING,
                    prefix + BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING,
                    prefix + BOSCHCOM_ENDPOINT_ZONE_USER_MODE,
                    prefix + BOSCHCOM_ENDPOINT_ZONE_NAME,
                    prefix + BOSCHCOM_ENDPOINT_ZONE_ICON,
                ]
                zone_bulk = (
                    await self.async_request_bulk(device_id, zone_endpoints) or {}
                )
                ref["temperatureActual"] = zone_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL
                )
                ref["temperatureHeatingSetpoint"] = zone_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING
                )
                ref["manualTemperatureHeating"] = zone_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING
                )
                ref["userMode"] = zone_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_ZONE_USER_MODE
                )
                ref["name"] = zone_bulk.get(prefix + BOSCHCOM_ENDPOINT_ZONE_NAME)
                ref["icon"] = zone_bulk.get(prefix + BOSCHCOM_ENDPOINT_ZONE_ICON)

            await asyncio.gather(*(populate_zone(ref) for ref in zone_refs))

        # --- Per-HC bulk ---
        heating_circuits = heating_circuits or {}
        hc_refs = heating_circuits.get("references", [])
        if hc_refs:

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_HEATING_CIRCUITS + "/" + hc_id
                hc_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATING_SEASON,
                    prefix + BOSCHCOM_ENDPOINT_HC_TYPE,
                    prefix + BOSCHCOM_ENDPOINT_HC_TYPE_ROOM_CONTROL,
                    prefix + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY,
                    prefix + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY,
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX,
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN,
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD,
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE,
                    prefix + BOSCHCOM_ENDPOINT_HC_CONTROL,
                ]
                hc_bulk = await self.async_request_bulk(device_id, hc_endpoints) or {}
                ref["supplyTemperatureSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT
                )
                ref["operatingSeason"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATING_SEASON
                )
                ref["type"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_TYPE)
                ref["typeRoomControl"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_TYPE_ROOM_CONTROL
                )
                ref["maxSupply"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY)
                ref["minSupply"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY)
                ref["heatCurveMax"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX
                )
                ref["heatCurveMin"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN
                )
                ref["nightSwitchMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE
                )
                ref["nightThreshold"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD
                )
                ref["roomInfluence"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE
                )
                ref["control"] = hc_bulk.get(prefix + BOSCHCOM_ENDPOINT_HC_CONTROL)

            await asyncio.gather(*(populate_hc(ref) for ref in hc_refs))

        # --- Per-DHW bulk ---
        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_DHW_CIRCUITS + "/" + dhw_id
                dhw_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_DWH_STATE,
                    prefix + BOSCHCOM_ENDPOINT_DWH_HOT_WATER_SYSTEM,
                    prefix + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
                    prefix + BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW,
                    prefix + BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION,
                    prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH,
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE,
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME,
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY,
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_LAST_RESULT,
                ]
                dhw_bulk = await self.async_request_bulk(device_id, dhw_endpoints) or {}
                ref["actualTemp"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP
                )
                ref["state"] = dhw_bulk.get(prefix + BOSCHCOM_ENDPOINT_DWH_STATE)
                ref["hotWaterSystem"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_HOT_WATER_SYSTEM
                )
                ref["operationMode"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE
                )
                ref["extraDhw"] = dhw_bulk.get(prefix + BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW)
                ref["extraDhwDuration"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_EXTRA_DHW_DURATION
                )
                ref["temperatureLevelHigh"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_HIGH
                )
                ref["thermalDisinfectState"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_STATE
                )
                ref["thermalDisinfectTime"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_TIME
                )
                ref["thermalDisinfectWeekDay"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_WEEKDAY
                )
                ref["thermalDisinfectLastResult"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_THERMAL_DISINFECT_LAST_RESULT
                )

            await asyncio.gather(*(populate_dhw(ref) for ref in dhw_refs))

        # --- Per-device bulk ---
        devices = devices or {}
        device_refs = devices.get("references", [])
        if device_refs:

            async def populate_device(ref: dict[str, Any]) -> None:
                dev_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_DEVICES + "/" + dev_id
                dev_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_TYPE,
                    prefix + BOSCHCOM_ENDPOINT_CHILD_LOCK,
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_ROOM_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_HUMIDITY,
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_SIGNAL,
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_BATTERY,
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_CURRENT_ROOM_SETPOINT,
                ]
                dev_bulk = await self.async_request_bulk(device_id, dev_endpoints) or {}
                ref["type"] = dev_bulk.get(prefix + BOSCHCOM_ENDPOINT_DEVICE_TYPE)
                ref["childLockEnabled"] = dev_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_CHILD_LOCK
                )
                ref["roomtemperature"] = dev_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_ROOM_TEMP
                )
                ref["actualHumidity"] = dev_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_HUMIDITY
                )
                ref["signal"] = dev_bulk.get(prefix + BOSCHCOM_ENDPOINT_DEVICE_SIGNAL)
                ref["battery"] = dev_bulk.get(prefix + BOSCHCOM_ENDPOINT_DEVICE_BATTERY)
                ref["currentRoomSetpoint"] = dev_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DEVICE_CURRENT_ROOM_SETPOINT
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
