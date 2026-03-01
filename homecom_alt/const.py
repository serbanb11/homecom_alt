"""Constants for homecom_alt library."""

from typing import Final

from aiohttp.client import ClientTimeout

OAUTH_DOMAIN: Final[str] = "https://singlekey-id.com"
OAUTH_LOGIN: Final[str] = "/auth/connect/authorize"
OAUTH_LOGIN_PARAMS: Final[dict] = {
    "redirect_uri": "com.bosch.tt.dashtt.pointt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
    "response_type": "code",
    "prompt": "login",
    "scope": (
        "openid email profile offline_access "
        "pointt.gateway.claiming pointt.gateway.removal "
        "pointt.gateway.list pointt.gateway.users "
        "pointt.gateway.resource.dashapp pointt.castt.flow.token-exchange "
        "bacon hcc.tariff.read"
    ),
    "code_challenge_method": "S256",
    "style_id": "tt_bsch",
}
OAUTH_ENDPOINT: Final[str] = "/auth/connect/token"
OAUTH_PARAMS: Final[dict] = {
    "grant_type": "authorization_code",
    "redirect_uri": "com.bosch.tt.dashtt.pointt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
}

OAUTH_LOGIN_PARAMS_BUDERUS: Final[dict] = {
    "redirect_uri": "com.buderus.tt.dashtt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
    "response_type": "code",
    "prompt": "login",
    "scope": (
        "openid email profile offline_access "
        "pointt.gateway.claiming pointt.gateway.removal "
        "pointt.gateway.list pointt.gateway.users "
        "pointt.gateway.resource.dashapp pointt.castt.flow.token-exchange "
        "bacon hcc.tariff.read"
    ),
    "code_challenge_method": "S256",
    "style_id": "tt_bud",
}
OAUTH_PARAMS_BUDERUS: Final[dict] = {
    "grant_type": "authorization_code",
    "redirect_uri": "com.buderus.tt.dashtt://app/login",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
}

OAUTH_REFRESH_PARAMS: Final[dict[str, str]] = {
    "grant_type": "refresh_token",
    "client_id": "762162C0-FA2D-4540-AE66-6489F189FADC",
}
OAUTH_BROWSER_VERIFIER: Final[str] = (
    "AZbpLzMvXigq_jz7_riwNDV8BQYT30prXGDyRHdQMo0GYre3si9YJfG4b1U-QWERtOiX_9mCJE2SAPvJMeM2yA"
)

BOSCHCOM_DOMAIN: Final[str] = "https://pointt-api.bosch-thermotechnology.com"
BOSCHCOM_ENDPOINT_GATEWAYS: Final[str] = "/pointt-api/api/v1/gateways/"
BOSCHCOM_ENDPOINT_FIRMWARE: Final[str] = "/resource/gateway/versionFirmware"
BOSCHCOM_ENDPOINT_BULK: Final[str] = "/pointt-api/api/v1/bulk"
BOSCHCOM_ENDPOINT_SYSTEM_INFO: Final[str] = "/resource/system/info"
BOSCHCOM_ENDPOINT_NOTIFICATIONS: Final[str] = "/resource/notifications"
BOSCHCOM_ENDPOINT_STANDARD: Final[str] = "/resource/airConditioning/standardFunctions"
BOSCHCOM_ENDPOINT_ADVANCED: Final[str] = "/resource/airConditioning/advancedFunctions"
BOSCHCOM_ENDPOINT_SWITCH: Final[str] = "/resource/airConditioning/switchPrograms/list"
BOSCHCOM_ENDPOINT_SWITCH_ENABLE: Final[str] = (
    "/resource/airConditioning/switchPrograms/enabled"
)
BOSCHCOM_ENDPOINT_SWITCH_PROGRAM: Final[str] = (
    "/resource/airConditioning/switchPrograms/activeProgram"
)
BOSCHCOM_ENDPOINT_TIME: Final[str] = "/resource/gateway/DateTime"
BOSCHCOM_ENDPOINT_TIME2: Final[str] = "/resource/gateway/dateTime"
BOSCHCOM_ENDPOINT_TIMER: Final[str] = "/resource/airConditioning/timers"
BOSCHCOM_ENDPOINT_PV_LIST: Final[str] = "/resource/pv/list"
BOSCHCOM_ENDPOINT_TEMP: Final[str] = "/resource/airConditioning/temperatureSetpoint"
BOSCHCOM_ENDPOINT_MODE: Final[str] = "/resource/airConditioning/operationMode"
BOSCHCOM_ENDPOINT_CONTROL: Final[str] = "/resource/airConditioning/acControl"
BOSCHCOM_ENDPOINT_FULL_POWER: Final[str] = "/resource/airConditioning/fullPowerMode"
BOSCHCOM_ENDPOINT_ECO: Final[str] = "/resource/airConditioning/ecoMode"
BOSCHCOM_ENDPOINT_FAN_SPEED: Final[str] = "/resource/airConditioning/fanSpeed"
BOSCHCOM_ENDPOINT_AIRFLOW_VERTICAL: Final[str] = (
    "/resource/airConditioning/airFlowVertical"
)
BOSCHCOM_ENDPOINT_AIRFLOW_HORIZONTAL: Final[str] = (
    "/resource/airConditioning/airFlowHorizontal"
)
BOSCHCOM_ENDPOINT_PLASMACLUSTER: Final[str] = (
    "/resource/airConditioning/airPurificationMode"
)
BOSCHCOM_ENDPOINT_AWAY_MODE: Final[str] = "/resource/system/awayMode/enabled"
BOSCHCOM_ENDPOINT_POWER_LIMITATION: Final[str] = (
    "/resource/system/powerLimitation/active"
)
BOSCHCOM_ENDPOINT_OUTDOOR_TEMP: Final[str] = (
    "/resource/system/sensors/temperatures/outdoor_t1"
)
BOSCHCOM_ENDPOINT_HOLIDAY_MODE: Final[str] = "/resource/holidayMode/activeModes"
BOSCHCOM_ENDPOINT_HS_TOTAL_CONSUMPTION: Final[str] = (
    "/resource/heatSources/emon/totalConsumption"
)
BOSCHCOM_ENDPOINT_HS_TYPE: Final[str] = "/resource/heatSources/hs1/type"
BOSCHCOM_ENDPOINT_HS_PUMP_TYPE: Final[str] = "/resource/heatSources/hs1/heatPumpType"
BOSCHCOM_ENDPOINT_HS_STARTS: Final[str] = "/resource/heatSources/hs1/numberOfStarts"
BOSCHCOM_ENDPOINT_HS_INFLOW_TEMP: Final[str] = (
    "/resource/heatSources/hs1/brineCircuit/collectorInflowTemp"
)
BOSCHCOM_ENDPOINT_HS_OUTFLOW_TEMP: Final[str] = (
    "/resource/heatSources/hs1/brineCircuit/collectorOutflowTemp"
)
BOSCHCOM_ENDPOINT_HS_RETURN_TEMP: Final[str] = "/resource/heatSources/returnTemperature"
BOSCHCOM_ENDPOINT_HS_HEAT_DEMAND: Final[str] = "/resource/heatSources/actualHeatDemand"
BOSCHCOM_ENDPOINT_HS_WORKING_TIME: Final[str] = (
    "/resource/heatSources/workingTime/totalSystem"
)
BOSCHCOM_ENDPOINT_HS_SUPPLY_TEMP: Final[str] = (
    "/resource/heatSources/actualSupplyTemperature"
)
BOSCHCOM_ENDPOINT_HS_MODULATION: Final[str] = "/resource/heatSources/actualModulation"
BOSCHCOM_ENDPOINT_HS_SYSTEM_PRESSURE: Final[str] = (
    "/resource/heatSources/systemPressure"
)
BOSCHCOM_ENDPOINT_HEATING_CIRCUITS: Final[str] = "/resource/heatingCircuits"
BOSCHCOM_ENDPOINT_HC_CONTROL_TYPE: Final[str] = "/controlType"
BOSCHCOM_ENDPOINT_HC_SUWI_MODE: Final[str] = "/currentSuWiMode"
BOSCHCOM_ENDPOINT_HC_HEATCOOL_MODE: Final[str] = "/heatCoolMode"
BOSCHCOM_ENDPOINT_HC_HEATING_TYPE: Final[str] = "/heatingType"
BOSCHCOM_ENDPOINT_HC_OPERATION_MODE: Final[str] = "/operationMode"
BOSCHCOM_ENDPOINT_HC_ROOM_TEMP: Final[str] = "/roomtemperature"
BOSCHCOM_ENDPOINT_HC_CURRENT_ROOM_SETPOINT: Final[str] = "/currentRoomSetpoint"
BOSCHCOM_ENDPOINT_HC_MANUAL_ROOM_SETPOINT: Final[str] = "/manualRoomSetpoint"
BOSCHCOM_ENDPOINT_HC_COOLING_ROOM_TEMP_SETPOINT: Final[str] = (
    "/cooling/roomTempSetpoint"
)
BOSCHCOM_ENDPOINT_HC_ACTUAL_HUMIDITY: Final[str] = "/actualHumidity"
BOSCHCOM_ENDPOINT_DHW_CIRCUITS: Final[str] = "/resource/dhwCircuits"
BOSCHCOM_ENDPOINT_DWH_OPERATION_MODE: Final[str] = "/operationMode"
BOSCHCOM_ENDPOINT_DWH_ACTUAL_TEMP: Final[str] = "/actualTemp"
BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL: Final[str] = "/temperatureLevels"
BOSCHCOM_ENDPOINT_DWH_TEMP_LEVEL_MANUAL: Final[str] = "/manualsetpoint"
BOSCHCOM_ENDPOINT_DWH_CURRENT_TEMP_LEVEL: Final[str] = "/currentTemperatureLevel"
BOSCHCOM_ENDPOINT_DWH_CHARGE: Final[str] = "/charge"
BOSCHCOM_ENDPOINT_DWH_CHARGE_REMAINING_TIME: Final[str] = "/chargeRemainingTime"
BOSCHCOM_ENDPOINT_DWH_CHARGE_DURATION: Final[str] = "/chargeDuration"
BOSCHCOM_ENDPOINT_DWH_CHARGE_SETPOINT: Final[str] = "/singleChargeSetpoint"
BOSCHCOM_ENDPOINT_DWH_AIRBOX: Final[str] = "/sensor/airBoxTemperature"
BOSCHCOM_ENDPOINT_DWH_FAN_SPEED: Final[str] = "/sensor/fanSpeed"
BOSCHCOM_ENDPOINT_DWH_INLET_TEMP: Final[str] = "/inletTemperature"
BOSCHCOM_ENDPOINT_DWH_OUTLET_TEMP: Final[str] = "/outletTemperature"
BOSCHCOM_ENDPOINT_DWH_WATER_FLOW: Final[str] = "/sensor/waterFlow"

BOSCHCOM_ENDPOINT_VENTILATION: Final[str] = "/resource/ventilation"
BOSCHCOM_ENDPOINT_VENTILATION_QUALITY: Final[str] = "/maxIndoorAirQuality"
BOSCHCOM_ENDPOINT_VENTILATION_OPERATION_MODE: Final[str] = "/operationMode"
BOSCHCOM_ENDPOINT_VENTILATION_HUMIDITY: Final[str] = "/maxRelativeHumidity"
BOSCHCOM_ENDPOINT_VENTILATION_FAN: Final[str] = "/exhaustFanLevel"
BOSCHCOM_ENDPOINT_VENTILATION_SUPPLY_TEMP: Final[str] = "/sensors/supplyTemp"
BOSCHCOM_ENDPOINT_VENTILATION_OUTDOOR_TEMP: Final[str] = "/sensors/outdoorTemp"
BOSCHCOM_ENDPOINT_VENTILATION_EXHAUST_TEMP: Final[str] = "/sensors/exhaustTemp"
BOSCHCOM_ENDPOINT_VENTILATION_EXTRACT_TEMP: Final[str] = "/sensors/extractTemp"
BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_QUALITY: Final[str] = (
    "/sensors/internalAirQuality"
)
BOSCHCOM_ENDPOINT_VENTILATION_INTERNAL_HUMIDITY: Final[str] = (
    "/sensors/internalHumidity"
)
BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_ENABLE: Final[str] = "/summerBypass/enable"
BOSCHCOM_ENDPOINT_VENTILATION_SUMMER_DURATION: Final[str] = "/summerBypass/duration"
BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_QUALITY: Final[str] = "/demand/indoorAirQuality"
BOSCHCOM_ENDPOINT_VENTILATION_DEMAND_HUMIDITY: Final[str] = "/demand/relativeHumidity"

BOSCHCOM_ENDPOINT_ZONES: Final[str] = "/resource/zones"
BOSCHCOM_ENDPOINT_ZONE_TEMP_ACTUAL: Final[str] = "/temperatureActual"
BOSCHCOM_ENDPOINT_ZONE_MANUAL_TEMP_HEATING: Final[str] = "/manualTemperatureHeating"
BOSCHCOM_ENDPOINT_ZONE_USER_MODE: Final[str] = "/userMode"
BOSCHCOM_ENDPOINT_ZONE_SETPOINT_TEMP_HEATING: Final[str] = "/temperatureHeatingSetpoint"

BOSCHCOM_ENDPOINT_HC_MAX_SUPPLY: Final[str] = "/maxSupply"
BOSCHCOM_ENDPOINT_HC_MIN_SUPPLY: Final[str] = "/minSupply"
BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MAX: Final[str] = "/heatCurveMax"
BOSCHCOM_ENDPOINT_HC_HEAT_CURVE_MIN: Final[str] = "/heatCurveMin"
BOSCHCOM_ENDPOINT_HC_SUPPLY_TEMP_SETPOINT: Final[str] = "/supplyTemperatureSetpoint"
BOSCHCOM_ENDPOINT_HC_NIGHT_SWITCH_MODE: Final[str] = "/nightSwitchMode"
BOSCHCOM_ENDPOINT_HC_CONTROL: Final[str] = "/control"
BOSCHCOM_ENDPOINT_HC_NIGHT_THRESHOLD: Final[str] = "/nightThreshold"
BOSCHCOM_ENDPOINT_HC_ROOM_INFLUENCE: Final[str] = "/roomInfluence"

BOSCHCOM_ENDPOINT_HS_FLAME: Final[str] = "/resource/heatSources/flameIndication"

BOSCHCOM_ENDPOINT_ENERGY_HISTORY: Final[str] = "/resource/energy/history"

BOSCHCOM_ENDPOINT_INDOOR_HUMIDITY: Final[str] = (
    "/resource/system/sensors/humidity/indoor_h1"
)

BOSCHCOM_ENDPOINT_DEVICES: Final[str] = "/resource/devices"
BOSCHCOM_ENDPOINT_CHILD_LOCK: Final[str] = "/thermostat/childLock/enabled"

# Commodule (wallbox/EV charger) endpoints
BOSCHCOM_ENDPOINT_CP: Final[str] = "/resource/rest/v1"
BOSCHCOM_ENDPOINT_CP_CONF: Final[str] = "/conf"
BOSCHCOM_ENDPOINT_CP_INFO: Final[str] = "/info"
BOSCHCOM_ENDPOINT_CP_TELEMETRY: Final[str] = "/telemetry"
BOSCHCOM_ENDPOINT_CP_CHARGELOG: Final[str] = "/chargelog"
BOSCHCOM_ENDPOINT_CP_CONF_PRICE: Final[str] = "/conf/price"
BOSCHCOM_ENDPOINT_CP_CONF_LOCKED: Final[str] = "/conf/locked"
BOSCHCOM_ENDPOINT_CP_CONF_AUTH: Final[str] = "/conf/auth"
BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE: Final[str] = "/conf/rfid/secure"
BOSCHCOM_ENDPOINT_ETH0_STATE: Final[str] = "/resource/gateway/eth0/state"

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

DEFAULT_TIMEOUT: Final[ClientTimeout] = ClientTimeout(total=15)

URLENCODED: Final[int] = 2
JSON: Final[int] = 1
