"""Type definitions for BHC."""

from dataclasses import dataclass


@dataclass
class ConnectionOptions:
    """Options for BHC."""

    username: str | None = None
    token: str | None = None
    refresh_token: str | None = None
    code: str | None = None
    auth_provider: bool = False
    brand: str = "bosch"


@dataclass(frozen=True)
class BHCDeviceGeneric:
    """Data class for Generic device."""

    device: str | None
    firmware: list | None
    notifications: list | None


@dataclass(frozen=True)
class BHCDeviceRac:
    """Data class for BHC device."""

    device: str | None
    firmware: list | None
    notifications: list | None
    stardard_functions: list | None
    advanced_functions: list | None
    switch_programs: list | None


@dataclass(frozen=True)
class BHCDeviceK40:
    """Data class for K40 and K30 BHC device."""

    device: str | None
    firmware: list | None
    notifications: list | None
    holiday_mode: list | None
    away_mode: list | None
    power_limitation: list | None
    outdoor_temp: list | None
    heat_sources: dict | None
    dhw_circuits: list | None
    heating_circuits: list | None
    ventilation: list | None
    zones: list | None
    flame_indication: dict | None
    energy_history: list | None
    hourly_energy_history: list | None
    indoor_humidity: list | None
    devices: list | None
    energy_gas_unit: dict | None = None


@dataclass(frozen=True)
class BHCDeviceIcom:
    """Data class for icom heat-pump BHC device.

    Reflects the trimmed endpoint surface in homecom-api-endpoints.md:
    no away/power_limitation/outdoor_t1/zones/flame_indication/devices/recordings.
    """

    device: str | None
    firmware: list | None
    notifications: list | None
    holiday_mode: list | None
    heat_sources: dict | None
    dhw_circuits: list | None
    heating_circuits: list | None
    solar_circuits: list | None
    ventilation: list | None
    system_info: dict | None
    system_bus: dict | None
    health_status: dict | None = None
    brand: dict | None = None


@dataclass(frozen=True)
class BHCDeviceRrc2:
    """Data class for rrc2 (Remeha Remote Control) BHC device.

    Per issue #78 response dumps the gateway actually serves the K40-style
    /heatingCircuits, /dhwCircuits, /zones namespaces — only the field set
    is trimmed.
    """

    device: str | None
    firmware: list | None
    notifications: list | None
    zones: list | None
    heating_circuits: list | None
    dhw_circuits: list | None
    heat_sources: dict | None
    away_mode: dict | None
    outdoor_temp: dict | None
    indoor_humidity: dict | None
    devices: list | None
    gateway_info: dict | None
    system_location: dict | None


@dataclass(frozen=True)
class BHCDeviceWddw2:
    """Data class for wddw2 BHC device."""

    device: str | None
    firmware: list | None
    notifications: list | None
    dhw_circuits: list | None
    heat_sources: dict | None = None
    water_total_consumption: dict | None = None
    holiday_mode: dict | None = None


@dataclass(frozen=True)
class BHCDeviceCommodule:
    """Data class for Commodule (wallbox/EV charger) device."""

    device: str | None
    firmware: list | None
    notifications: list | None
    charge_points: list | None
    eth0_state: dict | None
    wifi_state: dict | None
