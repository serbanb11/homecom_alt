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
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_HC_ACTIVE_SWITCH_PROGRAM,
    BOSCHCOM_ENDPOINT_HC_HOLIDAY_ACTIVATED,
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
    BOSCHCOM_ENDPOINT_SOLAR_CIRCUITS,
    BOSCHCOM_ENDPOINT_SYSTEM_BUS,
    BOSCHCOM_ENDPOINT_SYSTEM_HOLIDAY_MODES,
    BOSCHCOM_ENDPOINT_SYSTEM_INFO,
    MAX_CONCURRENT,
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
            health_status,
            brand,
            hs_type,
            hs_info,
            hs_return_temp,
            hs_total_starts,
            hs_supply_temp,
            hs_modulation,
            hs_total_consumption,
            hs_working_time,
            hs_system_pressure,
            hs_heat_demand,
            outdoor_temp,
        ) = await asyncio.gather(
            limited_call(self.async_get_notifications(device_id)),
            limited_call(self.async_get_hc(device_id)),
            limited_call(self.async_get_dhw(device_id)),
            limited_call(self.async_get_solar_circuits(device_id)),
            limited_call(self.async_get_ventilation_zones(device_id)),
            limited_call(self.async_get_system_holiday_modes(device_id)),
            limited_call(self.async_get_system_info(device_id)),
            limited_call(self.async_get_system_bus(device_id)),
            limited_call(self.async_get_system_health_status(device_id)),
            limited_call(self.async_get_system_brand(device_id)),
            limited_call(self.async_get_hs_type(device_id)),
            limited_call(self.async_get_heat_sources_info(device_id)),
            limited_call(self.async_get_hs_return_temp(device_id)),
            limited_call(self.async_get_hs_total_number_of_starts(device_id)),
            limited_call(self.async_get_hs_supply_temp(device_id)),
            limited_call(self.async_get_hs_modulation(device_id)),
            limited_call(self.async_get_hs_total_consumption(device_id)),
            limited_call(self.async_get_hs_working_time(device_id)),
            limited_call(self.async_get_hs_system_pressure(device_id)),
            limited_call(self.async_get_hs_heat_demand(device_id)),
            limited_call(self.async_get_outdoor_temp(device_id)),
        )

        heat_sources = {
            "type": hs_type or {},
            "info": hs_info or {},
            "returnTemperature": hs_return_temp or {},
            "numberOfStarts": hs_total_starts or {},
            "supplyTemperature": hs_supply_temp or {},
            "modulation": hs_modulation or {},
            "totalConsumption": hs_total_consumption or {},
            "workingTime": hs_working_time or {},
            "systemPressure": hs_system_pressure or {},
            "actualHeatDemand": hs_heat_demand or {},
            "outdoorTemp": outdoor_temp or {},
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

        # DHW circuits — fetch the writable + readable surface confirmed
        # working on icom heat pumps (issue #53 response dump).
        dhw_circuits = dhw_circuits or {}
        dhw_refs = dhw_circuits.get("references", [])
        if dhw_refs:

            async def populate_dhw(ref: dict[str, Any]) -> None:
                dhw_id = ref["id"].split("/")[-1]
                (
                    ref["operationMode"],
                    ref["actualTemp"],
                    ref["currentTemperatureLevel"],
                    ref["charge"],
                    ref["chargeRemainingTime"],
                    ref["chargeDuration"],
                    ref["singleChargeSetpoint"],
                    ref["holidayActivated"],
                    ref["currentSetpoint"],
                ) = await asyncio.gather(
                    limited_call(self.async_get_dhw_operation_mode(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_actual_temp(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_current_temp_level(device_id, dhw_id)
                    ),
                    limited_call(self.async_get_dhw_charge(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_charge_remaining_time(device_id, dhw_id)
                    ),
                    limited_call(self.async_get_dhw_charge_duration(device_id, dhw_id)),
                    limited_call(self.async_get_dhw_charge_setpoint(device_id, dhw_id)),
                    limited_call(
                        self.async_get_dhw_holiday_activated(device_id, dhw_id)
                    ),
                    limited_call(
                        self.async_get_dhw_current_setpoint(device_id, dhw_id)
                    ),
                )
                # temperatureLevels is a refEnum with off/low/high subnodes.
                # Fetch each level value so HA can show / edit them.
                temp_levels: dict[str, Any] = {}
                for level in ("off", "low", "high"):
                    temp_levels[level] = await limited_call(
                        self.async_get_dhw_temp_level(device_id, dhw_id, level)
                    )
                ref["temperatureLevels"] = temp_levels

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
            health_status=health_status or {},
            brand=brand or {},
        )
