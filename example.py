"""An example of using HomeCom alt package."""

import asyncio
import logging

from aiohttp import ClientSession

from homecom_alt import (
    ApiError,
    AuthFailedError,
    BHCDeviceRac,
    ConnectionOptions,
    HomeComAlt,
    HomeComK40,
    HomeComRac,
    InvalidSensorDataError,
)

logging.basicConfig(level=logging.DEBUG)

USERNAME = "user@example.com"
CODE = "your_oauth_code"


def print_status(data: BHCDeviceRac) -> None:
    """Print device status."""
    print(f"firmware: {data.firmware}")
    print(f"notifications: {data.notifications}")
    for ref in data.stardard_functions:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "operationMode":
                print(
                    f"operationMode current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case "acControl":
                print(
                    f"acControl current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case "fanSpeed":
                print(
                    f"fanSpeed current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case "airFlowHorizontal":
                print(
                    f"airFlowHorizontal current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case "airFlowVertical":
                print(
                    f"airFlowVertical current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case "temperatureSetpoint":
                print(
                    f"temperatureSetpoint current_value: {ref['value']}{ref['unitOfMeasure']}"
                )
                print(
                    f"temperatureSetpoint min_value: {ref['minValue']} max_value: {ref['maxValue']}"
                )
            case "roomTemperature":
                print(
                    f"roomTemperature current_value: {ref['value']} {ref['unitOfMeasure']}"
                )
            case _:
                pass

    for ref in data.advanced_functions:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "airPurificationMode":
                print(f"plasmacluster current_value: {ref['value']}")
            case "fullPowerMode":
                print(f"boost current_value: {ref['value']}")
            case "ecoMode":
                print(f"eco mode current_value: {ref['value']}")
            case "timers/on":
                print(
                    f"timer turn on current_value: {ref['value']} {ref['unitOfMeasure']}"
                )
                print(
                    f"timer turn on min_value: {ref['minValue']} max_value: {ref['maxValue']}"
                )
            case "timers/off":
                print(
                    f"timer turn off current_value: {ref['value']} {ref['unitOfMeasure']}"
                )
                print(
                    f"timer turn off min_value: {ref['minValue']} max_value: {ref['maxValue']}"
                )
            case _:
                pass

    for ref in data.switch_programs:
        normalized_id = ref["id"].split("/", 2)[-1]

        match normalized_id:
            case "switchPrograms/enabled":
                print(f"programs current_value: {ref['value']}")
            case "switchPrograms/activeProgram":
                print(
                    f"program current_value: {ref['value']}, allowed_values: {ref['allowedValues']}"
                )
            case _:
                pass


async def main() -> None:
    """Run main function."""
    options = ConnectionOptions(username=USERNAME, code=CODE)
    device_classes: dict[str, type[HomeComAlt]] = {
        "rac": HomeComRac,
        "k30": HomeComK40,
        "k40": HomeComK40,
    }

    async with ClientSession() as websession:
        try:
            base_instance = await HomeComAlt.create(
                websession, options, auth_provider=True
            )
            devices_raw = await base_instance.async_get_devices()
            devices = [
                device_classes[device["deviceType"]](
                    websession, options, device["deviceId"]
                )
                for device in devices_raw
                if device["deviceType"] in device_classes
            ]

            if not devices:
                print("No devices found")
                return

            for device in devices:
                print(f"Device={device.device_id}, type={device.device_type}")

            device_id = devices[0].device_id
            bhc = devices[0]
            data = await bhc.async_update(device_id)
            if bhc.device_type == "rac":
                print_status(data)

        except AuthFailedError as err:
            print(f"Authentication failed: {err}")
        except ApiError as err:
            print(f"API error: {err}")
        except InvalidSensorDataError as err:
            print(f"Invalid sensor data: {err}")


asyncio.run(main())
