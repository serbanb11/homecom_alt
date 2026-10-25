"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

from .bacon import (
    BaconMqttClient,
    HomeComBaconAp,
    HomeComBaconDevice,
    HomeComBaconRac,
    ParsedTopic,
    async_classify_bacon_device,
    async_get_bacon_devices,
    classify_bacon_device,
    decode_jwt_exp,
    decode_jwt_sub,
    generate_client_id,
    parse_topic,
)
from .base import HomeComAlt
from .commodule import HomeComCommodule
from .exceptions import (
    ApiError,
    AuthFailedError,
    BhcError,
    InvalidSensorDataError,
    MqttNotAuthorizedError,
    NotRespondingError,
    ProximityRequiredError,
    TokenStoreFullError,
)
from .generic import HomeComGeneric
from .icom import HomeComIcom
from .k40 import HomeComK40
from .local import HomeComK40Local
from .localfirst import HomeComK40LocalFirst, K40Update
from .model import (
    BHCDeviceBacon,
    BHCDeviceBaconRac,
    BHCDeviceCommodule,
    BHCDeviceGeneric,
    BHCDeviceIcom,
    BHCDeviceK40,
    BHCDeviceK40Local,
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
    "BHCDeviceBacon",
    "BHCDeviceBaconRac",
    "BHCDeviceCommodule",
    "BHCDeviceGeneric",
    "BHCDeviceIcom",
    "BHCDeviceK40",
    "BHCDeviceK40Local",
    "BHCDeviceRac",
    "BHCDeviceRrc2",
    "BHCDeviceWddw2",
    "BaconMqttClient",
    "BhcError",
    "ConnectionOptions",
    "HomeComAlt",
    "HomeComBaconAp",
    "HomeComBaconDevice",
    "HomeComBaconRac",
    "HomeComCommodule",
    "HomeComGeneric",
    "HomeComIcom",
    "HomeComK40",
    "HomeComK40Local",
    "HomeComK40LocalFirst",
    "HomeComRac",
    "HomeComRrc2",
    "HomeComWddw2",
    "InvalidSensorDataError",
    "K40Update",
    "MqttNotAuthorizedError",
    "NotRespondingError",
    "ParsedTopic",
    "ProximityRequiredError",
    "TokenStoreFullError",
    "async_classify_bacon_device",
    "async_get_bacon_devices",
    "classify_bacon_device",
    "decode_jwt_exp",
    "decode_jwt_sub",
    "generate_client_id",
    "parse_topic",
]
