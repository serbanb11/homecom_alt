# homecom-alt

Python wrapper for controlling devices managed by HomeCom Easy APP.

## How to use package
[Check example.py](example.py)

or

```python
"""An example of using HomeCom alt package."""
import asyncio
import logging

from aiohttp import ClientConnectorError, ClientError, ClientSession

from homecom_alt import (
    ApiError,
    AuthFailedError,
    ConnectionOptions,
    InvalidSensorDataError,
    HomeComAlt,
    BHCDevice,
)

logging.basicConfig(level=logging.DEBUG)

USERNAME = "user"
PASSWORD = "password"

def print_status(data: BHCDevice):
    print("firmware: {data.firmware}")
    print("notifications: {data.notifications}")
    for ref in data.stardard_functions:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "operationMode":
                print(f"operationMode current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case "acControl":
                print(f"acControl current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case "fanSpeed":
                print(f"fanSpeed current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case "airFlowHorizontal":
                print(f"airFlowHorizontal current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case "airFlowVertical":
                print(f"airFlowVertical current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case "temperatureSetpoint":
                print(f"temperatureSetpoint current_value: {ref["value"]}{ref["unitOfMeasure"]}")
                print(f"temperatureSetpoint min_value: {ref["minValue"]} max_value: {ref["maxValue"]}")
            case "roomTemperature":
                print(f"roomTemperature current_value: {ref["value"]}{ref["unitOfMeasure"]}")
            case _:
                pass

    for ref in data.advanced_functions:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "airPurificationMode":
                print(f"plasmacluster current_value: {ref["value"]}")
            case "fullPowerMode":
                print(f"boost current_value: {ref["value"]}")
            case "ecoMode":
                print(f"eco mode current_value: {ref["value"]}")
            case "timers/on":
                print(f"timer turn on current_value: {ref["value"]} {ref["unitOfMeasure"]}")
                print(f"timer turn on min_value: {ref["minValue"]} max_value: {ref["maxValue"]}")
            case "timers/off":
                print(f"timer turn off current_value: {ref["value"]} {ref["unitOfMeasure"]}")
                print(f"timer turn off min_value: {ref["minValue"]} max_value: {ref["maxValue"]}")
            case _:
                pass

    for ref in data.switch_programs:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "switchPrograms/enabled":
                print(f"programs current_value: {ref["value"]}")
            case "switchPrograms/activeProgram":
                print(f"program current_value: {ref["value"]}, allowed_values: {ref["allowedValues"]}")
            case _:
                pass

async def main():
    """Run main function."""
    options = ConnectionOptions(username=USERNAME, password=PASSWORD)

    async with ClientSession() as websession:
        bhc = await HomeComAlt.create(websession, options)

        try:
            data: dict[str, BHCDevice] = {}
            device_ids: list[str] = []
            # get devices synced with homecom easy
            devices = await bhc.async_get_devices()
            # get status for each device discovered
            for device in await devices:
                print(f"Device={device["deviceId"]}, type={device["deviceType"]}")
                device_ids.append(device["deviceId"])
            while True:
                device_id = input(f"Enter the device you want to control: {', '.join(device_ids)}")
                if device_id not in device_ids:
                    print("device_id not in the list of devices")
                    continue
                data: BHCDevice = await bhc.async_update(device_id)
                print_status(data)
                break

loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()

```
