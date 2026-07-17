"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

from .bacon import (
    BaconMqttClient,
    HomeComBaconRac,
    async_get_bacon_devices,
    decode_jwt_sub,
    generate_client_id,
)
from .base import HomeComAlt
from .commodule import HomeComCommodule
from .exceptions import (
    ApiError,
    AuthFailedError,
    BhcError,
    InvalidSensorDataError,
    NotRespondingError,
)
from .generic import HomeComGeneric
from .icom import HomeComIcom
from .k40 import HomeComK40
from .model import (
    BHCDeviceBaconRac,
    BHCDeviceCommodule,
    BHCDeviceGeneric,
    BHCDeviceIcom,
    BHCDeviceK40,
    BHCDeviceRac,
    BHCDeviceRrc2,
    BHCDeviceWddw2,
    ConnectionOptions,
)
from .rac import HomeComRac
from .rrc2 import HomeComRrc2
from .wddw2 import HomeComWddw2

__all__ = [
    "ApiError",
    "AuthFailedError",
    "BHCDeviceBaconRac",
    "BHCDeviceCommodule",
    "BHCDeviceGeneric",
    "BHCDeviceIcom",
    "BHCDeviceK40",
    "BHCDeviceRac",
    "BHCDeviceRrc2",
    "BHCDeviceWddw2",
    "BaconMqttClient",
    "BhcError",
    "ConnectionOptions",
    "HomeComAlt",
    "HomeComBaconRac",
    "HomeComCommodule",
    "HomeComGeneric",
    "HomeComIcom",
    "HomeComK40",
    "HomeComRac",
    "HomeComRrc2",
    "HomeComWddw2",
    "InvalidSensorDataError",
    "NotRespondingError",
    "async_get_bacon_devices",
    "decode_jwt_sub",
    "generate_client_id",
]
