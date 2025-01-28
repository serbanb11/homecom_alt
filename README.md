# homecom-alt

Python wrapper for controlling devices managed by HomeCom Easy APP.

## How to use package

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
    NettigoAirMonitor,
)

logging.basicConfig(level=logging.DEBUG)

USERNAME = "user"
PASSWORD = "password"


async def main():
    """Run main function."""
    options = ConnectionOptions(username=USERNAME, password=PASSWORD)

    async with ClientSession() as websession:
        hca = await HomeComAlt.create(websession, options)

        try:
            data = await hca.async_update()
        except (
            ApiError,
            AuthFailedError,
            ClientConnectorError,
            ClientError,
            InvalidSensorDataError,
            asyncio.TimeoutError,
        ) as error:
            print(f"Error: {error}")
        else:
            print(f"Auth enabled: {hca.auth_enabled}")
            print(f"Firmware: {hca.software_version}")
            print(f"Data: {data}")


loop = asyncio.new_event_loop()
loop.run_until_complete(main())
loop.close()

```
