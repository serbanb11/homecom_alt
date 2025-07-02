"""An example of using homecom_alt package."""

import asyncio
import logging
import sys
import json
from dataclasses import asdict

from aiohttp import ClientConnectorError, ClientError, ClientSession

from homecom_alt import (
    ApiError,
    AuthFailedError,
    BHCDeviceK40,
    BHCDeviceRac,
    ConnectionOptions,
    HomeComAlt,
    HomeComK40,
    HomeComRac,
    InvalidSensorDataError,
)

logging.basicConfig(level=logging.DEBUG)

USERNAME = "username"
PASSWORD = "password"


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


def print_status_k40(data: BHCDeviceK40) -> None:
    """Print device status."""
    print(json.dumps(asdict(data), indent=4))


async def main() -> None:
    """Run main function."""
    options = ConnectionOptions(username=USERNAME, password=PASSWORD)
    device_classes: dict[str, type[HomeComAlt]] = {
        "rac": HomeComRac,
        "k30": HomeComK40,
        "k40": HomeComK40,
    }

    async with ClientSession() as websession:
        try:
            base_instance = await HomeComAlt.create(websession, options)
            devices = await base_instance.async_get_devices()
            devices = [
                device_classes[device["deviceType"]](
                    websession, options, device["deviceId"]
                )
                for device in await devices
                if device["deviceType"] in device_classes
            ]
            device_ids: list[str] = []
            # get devices synced with homecom easy
            # print each device discovered
            for device in devices:
                print(f"Device={device.device_id}, type={device.device_type}")
                device_ids.append(device.device_id)

            if not devices:
                print("No devices found")
                sys.exit(0)

            while True:
                if len(device_ids) == 1:
                    device_id = device_ids[0]
                else:
                    device_id = input(
                        f"Enter the device you want to control: {', '.join(device_ids)}"
                    )
                if device_id not in device_ids:
                    print("device_id not in the list of devices")
                    continue
                bhc = next(
                    (device for device in devices if device.device_id == device_id),
                    None,
                )
                data = await bhc.async_update(device_id)
                if bhc.device_type == "rac":
                    print_status(data)
                if bhc.device_type in ("k30", "k40"):
                    print_status_k40(data)
                break

            allowed_bool = ["on", "off"]
            while True:
                print("Choose an action for device ", device_id)
                print("1. Get current status")
                print("2. Get current time")
                print("3. Turn device ON")
                print("4. Turn device OFF")
                print("5. Set HVAC mode")
                print("6. Set Fan mode")
                print("7. Set tempreture")
                print("8. Set airFlowHorizontal mode")
                print("9. Set airFlowVertical mode")
                print("10. Set plasmacluster mode")
                print("11. Set boost mode")
                print("12. Set eco mode")
                print("13. Set timer on")
                print("14. Set timer off")
                print("15. Turn program ON")
                print("16. Turn program OFF")
                print("17. Set active program")
                print("18. change device")
                print("0. Exit")
                choice = input("Enter the number of your choice: ")

                if choice == "1":
                    data = await bhc.async_update(device_id)
                    if bhc.device_type == "rac":
                        print_status(data)
                    if bhc.device_type in ("k30", "k40"):
                        print_status_k40(data)
                elif choice == "2":
                    time: dict = await bhc.async_get_time(device_id)
                    print(f"time: {time['value']}")
                elif choice == "3":
                    await bhc.async_turn_on(device_id)
                elif choice == "4":
                    await bhc.async_turn_off(device_id)
                elif choice == "5":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "operationMode" in ref["id"]
                        ),
                        None,
                    )
                    print("Allowed HVAC modes:", ", ".join(values["allowedValues"]))
                    hvac_mode = input("Enter the HVAC mode: ").strip().lower()
                    if hvac_mode in values["allowedValues"]:
                        await bhc.async_set_hvac_mode(device_id, hvac_mode)
                    else:
                        print("Invalid HVAC mode.")
                elif choice == "6":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "fanSpeed" in ref["id"]
                        ),
                        None,
                    )
                    print("Allowed fan modes:", ", ".join(values["allowedValues"]))
                    fan_mode = input("Enter the fan mode: ").strip().lower()
                    if fan_mode in values["allowedValues"]:
                        await bhc.async_set_fan_mode(device_id, fan_mode)
                    else:
                        print("Invalid fan mode.")
                elif choice == "7":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "temperatureSetpoint" in ref["id"]
                        ),
                        None,
                    )
                    print(
                        "min_temp: ",
                        values["minValue"],
                        "max_temp: ",
                        values["maxValue"],
                    )
                    temp = round(float(input("Enter temp: ").strip()), 1)
                    if temp > values["minValue"] and temp < values["maxValue"]:
                        await bhc.async_set_temperature(device_id, temp)
                    else:
                        print("Invalid temperature.")
                elif choice == "8":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "airFlowHorizontal" in ref["id"]
                        ),
                        None,
                    )
                    print(
                        "Allowed airFlowHorizontal modes:",
                        ", ".join(values["allowedValues"]),
                    )
                    air_mode = (
                        input("Enter airFlowHorizontal fan mode: ").strip().lower()
                    )
                    if air_mode in values["allowedValues"]:
                        await bhc.async_set_horizontal_swing_mode(device_id, air_mode)
                    else:
                        print("Invalid airFlowHorizontal mode.")
                elif choice == "9":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "airFlowVertical" in ref["id"]
                        ),
                        None,
                    )
                    print(
                        "Allowed airFlowVertical modes:",
                        ", ".join(values["allowedValues"]),
                    )
                    air_mode = input("Enter the airFlowVertical mode: ").strip().lower()
                    if air_mode in values["allowedValues"]:
                        await bhc.async_set_vertical_swing_mode(device_id, air_mode)
                    else:
                        print("Invalid airFlowVertical mode.")
                elif choice == "10":
                    print("Allowed plasmacluster mode:", ", ".join(allowed_bool))
                    mode = input("Enter the plasmacluster mode: ").strip().lower()
                    if mode in allowed_bool:
                        await bhc.async_set_plasmacluster(device_id, bool(mode == "on"))
                    else:
                        print("Invalid mode.")
                elif choice == "11":
                    print("Allowed boost mode:", ", ".join(allowed_bool))
                    mode = input("Enter the boost mode: ").strip().lower()
                    if mode in allowed_bool:
                        await bhc.async_set_boost(device_id, bool(mode == "on"))
                    else:
                        print("Invalid mode.")
                elif choice == "12":
                    print("Allowed eco modes:", ", ".join(allowed_bool))
                    mode = input("Enter the eco mode: ").strip().lower()
                    if mode in allowed_bool:
                        await bhc.async_set_eco(device_id, bool(mode == "on"))
                    else:
                        print("Invalid mode.")
                elif choice == "13":
                    values = next(
                        (
                            ref
                            for ref in data.advanced_functions
                            if "timers/on" in ref["id"]
                        ),
                        None,
                    )
                    print(
                        "min_value: ",
                        values["minValue"],
                        values["unitOfMeasure"],
                        "max_value: ",
                        values["maxValue"],
                        values["unitOfMeasure"],
                    )
                    timer = int(input("Enter timer: ").strip())
                    if timer >= values["minValue"] and timer <= values["maxValue"]:
                        await bhc.async_time_on(device_id, timer)
                    else:
                        print("Invalid timer value.")
                elif choice == "14":
                    values = next(
                        (
                            ref
                            for ref in data.advanced_functions
                            if "timers/off" in ref["id"]
                        ),
                        None,
                    )
                    print(
                        "min_value: ",
                        values["minValue"],
                        values["unitOfMeasure"],
                        "max_value: ",
                        values["maxValue"],
                        values["unitOfMeasure"],
                    )
                    timer = int(input("Enter timer: ").strip())
                    if timer >= values["minValue"] and timer <= values["maxValue"]:
                        await bhc.async_time_off(device_id, timer)
                    else:
                        print("Invalid timer value.")
                elif choice == "15":
                    await bhc.async_control_program(device_id, "on")
                elif choice == "16":
                    await bhc.async_control_program(device_id, "off")
                elif choice == "17":
                    values = next(
                        (
                            ref
                            for ref in data.stardard_functions
                            if "activeProgram" in ref["id"]
                        ),
                        None,
                    )
                    print("Allowed programs:", ", ".join(values["allowedValues"]))
                    program = input("Enter the program: ").strip().lower()
                    if program in values["allowedValues"]:
                        await bhc.async_switch_program(device_id, program)
                    else:
                        print("Invalid program.")
                elif choice == "18":
                    temp_device_id = input(
                        f"Enter the device you want to control: {', '.join(device_ids)} "
                    )
                    if temp_device_id not in device_ids:
                        print("device_id not in the list of devices")
                        continue
                    device_id = temp_device_id
                    bhc = next(
                        (device for device in devices if device.device_id == device_id),
                        None,
                    )
                    data: BHCDeviceRac = await bhc.async_update(device_id)
                    print_status(data)
                elif choice == "0":
                    print("Exiting, Goodbye!")
                    break
                else:
                    print("Invalid choice. Please select a valid option from 0 to 18.")
        except (
            TimeoutError,
            ApiError,
            AuthFailedError,
            ClientConnectorError,
            ClientError,
            InvalidSensorDataError,
        ) as error:
            print(f"Error: {error}")


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()
