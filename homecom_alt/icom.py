"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
    BOSCHCOM_ENDPOINT_DHW_CURRENT_SETPOINT,
    BOSCHCOM_ENDPOINT_DHW_HOLIDAY_ACTIVATED,
    BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
    BOSCHCOM_ENDPOINT_DWH_CHARGE,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
    BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
    BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
    BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED,
    BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
    BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
    BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
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
    BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND,
    BOSCHCOM_ENDPOINT_HS_INFO,
    BOSCHCOM_ENDPOINT_HS_MODULATION,
    BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
    BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
    BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE,
    BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
    BOSCHCOM_ENDPOINT_HS_TOTAL_NUMBER_OF_STARTS,
    BOSCHCOM_ENDPOINT_HS_TYPE,
    BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
    BOSCHCOM_ENDPOINT_NOTIFICATIONS,
    BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
    BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS,
    BOSCHCOM_ENDPOINT_SYSTEM_BRAND,
    BOSCHCOM_ENDPOINT_SYSTEM_BUS,
    BOSCHCOM_ENDPOINT_SYSTEM_HEALTH_STATUS,
    BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES,
    BOSCHCOM_ENDPOINT_SYSTEM_INFO,
    BOSCHCOM_ENDPOINT_VENTILATION,
    BOSCHCOM_ENDPOINT_VENTILATION_FAN,
    BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
)
from .k40 import HomeComK40
from .model import (
    BHCDeviceIcom,
)

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


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

    async def async_get_dhw_current_setpoint(self, device_id: str, dhw_id: str) -> Any:
        """Get the live DHW current setpoint for a circuit."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_DHW_CIRCUITS
            + "/"
            + dhw_id
            + BOSCHCOM_ENDPOINT_DHW_CURRENT_SETPOINT,
        )
        return await self._to_data(response)

    async def async_update(  # type: ignore[override]  # noqa: PLR0915
        self, device_id: str
    ) -> BHCDeviceIcom:
        """Fetch the icom-supported endpoint subset and return a BHCDeviceIcom.

        Returns a different dataclass type than the inherited K40 method, so
        mypy needs to ignore the variance here. Treat coordinator code as
        polymorphic over BHCDeviceK40 | BHCDeviceIcom.
        """
        await self.get_token()

        firmware = await self.async_get_firmware(device_id)

        # --- Static endpoints: single bulk call ---
        bulk_endpoints = [
            BOSCHCOM_ENDPOINT_NOTIFICATIONS,
            BOSCHCOM_ENDPOINT_HEATING_CIRCUITS,
            BOSCHCOM_ENDPOINT_DHW_CIRCUITS,
            BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS,
            BOSCHCOM_ENDPOINT_VENTILATION,
            BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES,
            BOSCHCOM_ENDPOINT_SYSTEM_INFO,
            BOSCHCOM_ENDPOINT_SYSTEM_BUS,
            BOSCHCOM_ENDPOINT_SYSTEM_HEALTH_STATUS,
            BOSCHCOM_ENDPOINT_SYSTEM_BRAND,
            BOSCHCOM_ENDPOINT_HS_TYPE,
            BOSCHCOM_ENDPOINT_HS_INFO,
            BOSCHCOM_ENDPOINT_HS_RETURN_TEMP,
            BOSCHCOM_ENDPOINT_HS_TOTAL_NUMBER_OF_STARTS,
            BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP,
            BOSCHCOM_ENDPOINT_HS_MODULATION,
            BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION,
            BOSCHCOM_ENDPOINT_HS_WORKING_TIME,
            BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE,
            BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND,
            BOSCHCOM_ENDPOINT_OUTDOOR_TEMP,
        ]
        bulk_response = await self.async_request_bulk(device_id, bulk_endpoints) or {}

        notifications = bulk_response.get(BOSCHCOM_ENDPOINT_NOTIFICATIONS)
        heating_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_HEATING_CIRCUITS)
        dhw_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_DHW_CIRCUITS)
        solar_circuits = bulk_response.get(BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS)
        ventilation = bulk_response.get(BOSCHCOM_ENDPOINT_VENTILATION)
        holiday_modes = bulk_response.get(BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES)
        system_info = bulk_response.get(BOSCHCOM_ENDPOINT_SYSTEM_INFO)
        system_bus = bulk_response.get(BOSCHCOM_ENDPOINT_SYSTEM_BUS)
        health_status = bulk_response.get(BOSCHCOM_ENDPOINT_SYSTEM_HEALTH_STATUS)
        brand = bulk_response.get(BOSCHCOM_ENDPOINT_SYSTEM_BRAND)
        outdoor_temp = bulk_response.get(BOSCHCOM_ENDPOINT_OUTDOOR_TEMP)

        heat_sources = {
            "type": bulk_response.get(BOSCHCOM_ENDPOINT_HS_TYPE) or {},
            "info": bulk_response.get(BOSCHCOM_ENDPOINT_HS_INFO) or {},
            "returnTemperature": bulk_response.get(BOSCHCOM_ENDPOINT_HS_RETURN_TEMP)
            or {},
            "numberOfStarts": bulk_response.get(
                BOSCHCOM_ENDPOINT_HS_TOTAL_NUMBER_OF_STARTS
            )
            or {},
            "supplyTemperature": bulk_response.get(BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP)
            or {},
            "modulation": bulk_response.get(BOSCHCOM_ENDPOINT_HS_MODULATION) or {},
            "totalConsumption": bulk_response.get(
                BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION
            )
            or {},
            "workingTime": bulk_response.get(BOSCHCOM_ENDPOINT_HS_WORKING_TIME) or {},
            "systemPressure": bulk_response.get(BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE)
            or {},
            "actualHeatDemand": bulk_response.get(BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND)
            or {},
            "outdoorTemp": outdoor_temp or {},
        }

        # --- Per-HC bulk ---
        heating_circuits = heating_circuits or {}
        hc_refs = heating_circuits.get("references", [])
        if hc_refs:

            async def populate_hc(ref: dict[str, Any]) -> None:
                hc_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_HEATING_CIRCUITS + "/" + hc_id
                hc_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE,
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_SWITCH_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED,
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMPERATURE_LEVELS,
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_COMFORT2,
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_ECO,
                    prefix + BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM,
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_A,
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_B,
                ]
                hc_bulk = await self.async_request_bulk(device_id, hc_endpoints) or {}
                ref["operationMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_OPERATION_MODE
                )
                ref["controlType"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE
                )
                ref["currentSuWiMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_MODE
                )
                ref["suWiSwitchMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SUWI_SWITCH_MODE
                )
                ref["currentRoomSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT
                )
                ref["manualRoomSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT
                )
                ref["temporaryRoomSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMPORARY_ROOM_SETPOINT
                )
                ref["roomtemperature"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_ROOM_TEMP
                )
                ref["coolingRoomTempSetpoint"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT
                )
                ref["holidayActivated"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED
                )
                ref["temperatureLevels"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMPERATURE_LEVELS
                )
                ref["temperatureLevelComfort2"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_COMFORT2
                )
                ref["temperatureLevelEco"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_TEMP_LEVELS_ECO
                )
                ref["activeSwitchProgram"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM
                )
                ref["switchProgramMode"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_MODE
                )
                ref["switchProgramA"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_A
                )
                ref["switchProgramB"] = hc_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HC_SWITCH_PROGRAM_B
                )

            await asyncio.gather(*(populate_hc(ref) for ref in hc_refs))
        else:
            heating_circuits["references"] = []

        # --- Per-DHW bulk ---
        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_DHW_CIRCUITS + "/" + dhw_id
                dhw_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE,
                    prefix + BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL,
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE,
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME,
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION,
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_DHW_HOLIDAY_ACTIVATED,
                    prefix + BOSCHCOM_ENDPOINT_DHW_CURRENT_SETPOINT,
                    prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/off",
                    prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/low",
                    prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/high",
                ]
                dhw_bulk = await self.async_request_bulk(device_id, dhw_endpoints) or {}
                ref["operationMode"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE
                )
                ref["actualTemp"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP
                )
                ref["currentTemperatureLevel"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL
                )
                ref["charge"] = dhw_bulk.get(prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE)
                ref["chargeRemainingTime"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME
                )
                ref["chargeDuration"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION
                )
                ref["singleChargeSetpoint"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT
                )
                ref["holidayActivated"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DHW_HOLIDAY_ACTIVATED
                )
                ref["currentSetpoint"] = dhw_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_DHW_CURRENT_SETPOINT
                )
                ref["temperatureLevels"] = {
                    "off": dhw_bulk.get(
                        prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/off"
                    ),
                    "low": dhw_bulk.get(
                        prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/low"
                    ),
                    "high": dhw_bulk.get(
                        prefix + BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL + "/high"
                    ),
                }

            await asyncio.gather(*(populate_dhw(ref) for ref in dhw_refs))
        else:
            dhw_circuits["references"] = []

        # Solar circuits — listing only (per spec).
        solar_circuits = solar_circuits or {}
        solar_refs = solar_circuits.get("references", [])

        # --- Per-ventilation bulk ---
        ventilation = ventilation or {}
        vent_refs = ventilation.get("references", [])
        if vent_refs:

            async def populate_vent(ref: dict[str, Any]) -> None:
                zone_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_VENTILATION + "/" + zone_id
                vent_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_FAN,
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE,
                ]
                vent_bulk = (
                    await self.async_request_bulk(device_id, vent_endpoints) or {}
                )
                ref["exhaustFanLevel"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_FAN
                )
                ref["operationMode"] = vent_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE
                )

            await asyncio.gather(*(populate_vent(ref) for ref in vent_refs))

        # --- Per-holiday-mode bulk ---
        holiday_modes = holiday_modes or {}
        hm_refs = holiday_modes.get("references", [])
        if hm_refs:

            async def populate_hm(ref: dict[str, Any]) -> None:
                hm_id = ref["id"].split("/")[-1]
                prefix = BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES + "/" + hm_id
                hm_endpoints = [
                    prefix + BOSCHCOM_ENDPOINT_HM_DHW_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HM_HC_MODE,
                    prefix + BOSCHCOM_ENDPOINT_HM_FIX_TEMP,
                    prefix + BOSCHCOM_ENDPOINT_HM_START_STOP,
                ]
                hm_bulk = await self.async_request_bulk(device_id, hm_endpoints) or {}
                ref["dhwMode"] = hm_bulk.get(prefix + BOSCHCOM_ENDPOINT_HM_DHW_MODE)
                ref["hcMode"] = hm_bulk.get(prefix + BOSCHCOM_ENDPOINT_HM_HC_MODE)
                ref["fixTemperature"] = hm_bulk.get(
                    prefix + BOSCHCOM_ENDPOINT_HM_FIX_TEMP
                )
                ref["startStop"] = hm_bulk.get(prefix + BOSCHCOM_ENDPOINT_HM_START_STOP)

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
            health_status=health_status or {},
            brand=brand or {},
        )
