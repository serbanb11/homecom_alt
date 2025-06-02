"""Type definitions for BHC."""

from dataclasses import dataclass


@dataclass
class ConnectionOptions:
    """Options for BHC."""

    username: str | None = None
    password: str | None = None
    token: str | None = None
    refresh_token: str | None = None

    def __post_init__(self) -> None:
        """Call after initialization."""
        if self.username is not None and self.password is None:
            raise ValueError("Supply both username and password")


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
    """Data class for BHC device."""

    device: str | None
    firmware: list | None
    notifications: list | None
    holiday_mode: list | None
    away_mode: list | None
    consumption: list | None
    power_limitation: list | None
    hs_pump_type: list | None
    dhw_circuits: list | None
    heating_circuits: list | None
