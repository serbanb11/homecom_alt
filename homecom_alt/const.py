"""Constants for nettigo-air-monitor library."""

from typing import Final

from aiohttp.client import ClientTimeout

OAUTH_DOMAIN: Final[str] = "https://singlekey-id.com"
OAUTH_LOGIN: Final[str] = "/auth/connect/authorize"
OAUTH_LOGIN_PARAMS: Final[dict] = {
    "redirect_uri": "com.bosch.tt.dashtt.pointt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
    "response_type": "code",
    "prompt": "login",
    "scope": "openid email profile offline_access pointt.gateway.claiming pointt.gateway.removal pointt.gateway.list pointt.gateway.users pointt.gateway.resource.dashapp pointt.castt.flow.token-exchange bacon hcc.tariff.read",
    "code_challenge_method": "S256",
    "style_id": "tt_bsch",
}
OAUTH_ENDPOINT: Final[str] = "/auth/connect/token"
OAUTH_PARAMS: Final[dict] = {
    "grant_type": "authorization_code",
    "redirect_uri": "com.bosch.tt.dashtt.pointt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
}

OAUTH_REFRESH_PARAMS: Final[str] = {
    "grant_type": "refresh_token",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
}

BOSCHCOM_DOMAIN: Final[str] = "https://pointt-api.bosch-thermotechnology.com"
BOSCHCOM_ENDPOINT_GATEWAYS: Final[str] = "/pointt-api/api/v1/gateways/"
BOSCHCOM_ENDPOINT_FIRMWARE: Final[str] = "/resource/gateway/versionFirmware"
BOSCHCOM_ENDPOINT_NOTIFICATIONS: Final[str] = "/resource/notifications"
BOSCHCOM_ENDPOINT_STANDARD: Final[str] = "/resource/airConditioning/standardFunctions"
BOSCHCOM_ENDPOINT_ADVANCED: Final[str] = "/resource/airConditioning/advancedFunctions"
BOSCHCOM_ENDPOINT_SWITCH: Final[str] = "/resource/airConditioning/switchPrograms/list"
BOSCHCOM_ENDPOINT_SWITCH_ENABLE: Final[str] = "/resource/airConditioning/switchPrograms/enabled"
BOSCHCOM_ENDPOINT_SWITCH_PROGRAM: Final[str] = (
    "/resource/airConditioning/switchPrograms/activeProgram"
)
BOSCHCOM_ENDPOINT_TIME: Final[str] = "/resource/gateway/DateTime"
BOSCHCOM_ENDPOINT_TIMER: Final[str] = "/resource/airConditioning/timers"
BOSCHCOM_ENDPOINT_PV_LIST: Final[str] = "/resource/pv/list"
BOSCHCOM_ENDPOINT_TEMP: Final[str] = "/resource/airConditioning/temperatureSetpoint"
BOSCHCOM_ENDPOINT_MODE: Final[str] = "/resource/airConditioning/operationMode"
BOSCHCOM_ENDPOINT_CONTROL: Final[str] = "/resource/airConditioning/acControl"
BOSCHCOM_ENDPOINT_FULL_POWER: Final[str] = "/resource/airConditioning/fullPowerMode"
BOSCHCOM_ENDPOINT_ECO: Final[str] = "/resource/airConditioning/ecoMode"
BOSCHCOM_ENDPOINT_FAN_SPEED: Final[str] = "/resource/airConditioning/fanSpeed"
BOSCHCOM_ENDPOINT_AIRFLOW_VERTICAL: Final[str] = "/resource/airConditioning/airFlowVertical"
BOSCHCOM_ENDPOINT_AIRFLOW_HORIZONTAL: Final[str] = "/resource/airConditioning/airFlowHorizontal"
BOSCHCOM_ENDPOINT_PLASMACLUSTER: Final[str] = "/resource/airConditioning/airPurificationMode"

ATTR_NOTIFICATIONS: Final[str] = "notifications"
ATTR_FIRMWARE: Final[str] = "fw"
ATTR_MODE: Final[str] = "operationMode"
ATTR_SPEED: Final[str] = "fanSpeed"
ATTR_HORIZONTAL: Final[str] = "airFlowHorizontal"
ATTR_VERTICAL: Final[str] = "airFlowVertical"
ATTR_TEMP: Final[str] = "temperatureSetpoint"
ATTR_ROOM_TEMP: Final[str] = "roomTemperature"
ATTR_AIR_PURIFICATION: Final[str] = "airPurificationMode"
ATTR_FULL_POWER: Final[str] = "fullPowerMode"
ATTR_ECO_MODE: Final[str] = "ecoMode"
ATTR_TIMERS_ON: Final[str] = "timersOn"
ATTR_TIMERS_OFF: Final[str] = "timersOff"

DEFAULT_TIMEOUT: Final[ClientTimeout] = ClientTimeout(total=5)
