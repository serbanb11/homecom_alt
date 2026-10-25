# homecom-alt

[![PyPI version](https://img.shields.io/pypi/v/homecom_alt)](https://pypi.org/project/homecom_alt/)
[![Python](https://img.shields.io/pypi/pyversions/homecom_alt)](https://pypi.org/project/homecom_alt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Async Python wrapper for controlling Bosch Thermotechnology devices managed by the **HomeCom Easy** app. Communicates with the `pointt-api.bosch-thermotechnology.com` REST API using OAuth2 (SingleKey ID) authentication.

## Installation

```bash
pip install homecom_alt
```

## Device support

| Device type | Class | Data model |
|---|---|---|
| `rac` | `HomeComRac` | `BHCDeviceRac` |
| `k40` / `k30` | `HomeComK40` | `BHCDeviceK40` |
| `icom` | `HomeComIcom` | `BHCDeviceIcom` |
| `rrc2` | `HomeComRrc2` | `BHCDeviceRrc2` |
| `wddw2` | `HomeComWddw2` | `BHCDeviceWddw2` |
| `commodule` | `HomeComCommodule` | `BHCDeviceCommodule` |
| `generic` | `HomeComGeneric` | `BHCDeviceGeneric` |
| `bacon_rac` | `HomeComBaconRac` | `BHCDeviceBacon` |
| `bacon_ap` | `HomeComBaconAp` | `BHCDeviceBacon` |

### Matter-commissioned ACs and air purifiers (Bacon)

Bosch Climate ACs and Air 4000i-class air purifiers commissioned **over Matter**
in the HomeCom Easy app (serials like `86DM-580-…`) are not pointt gateways, so
they never appear in `HomeComAlt.async_get_devices()`. They are managed by
Bosch's *bacon* backend and controlled through an AWS-IoT-style **device shadow
over MQTT 5 (WebSocket)**, which requires the extra `paho-mqtt` dependency
(installed automatically).

- Discover them with `async_get_bacon_devices(session, token, region)` — returns
  the same `{"deviceId", "deviceType": "bacon_rac"}` shape as the REST discovery.
  The claiming endpoint hands out bare serials, so every device is typed
  `bacon_rac` at this point.
- Open one shared `BaconMqttClient` per account (`async_connect(token, sub)`).
- Tell the families apart with `await async_classify_bacon_device(client, serial)`
  → `"bacon_rac"` or `"bacon_ap"`. It reads `topics/info.appliance.type` the way
  the app does, falling back to the `$package` shadow and the state shadow.
- Wrap each serial in `HomeComBaconRac` (`async_set_power` / `async_set_mode` /
  `async_set_temperature` / `async_set_fan` / `async_set_swing` /
  `async_set_feature`) or `HomeComBaconAp` (`async_set_power` / `async_set_mode`
  with `auto`/`manual`/`silent`, `async_set_fan_speed` — which also selects
  `manual`, as the app only offers a speed there —, `async_set_timer`,
  `async_set_feature` for child lock / light / display, `async_reset_filter`).
  Both expose `async_update()` plus the push-only `sensor` / `metadata` / `info`.
- `async_get_shadow(serial, "schedule" | "$package")` reads the other shadows.
- The region defaults to `euc1` (eu-central-1); `use1` also exists.

## Authentication

`ConnectionOptions` supports two auth flows:

- **OAuth2 code flow** (recommended): provide `username` and `code` obtained from the SingleKey ID authorization endpoint, and set `auth_provider=True` when calling `HomeComAlt.create()`.
- **Token reuse**: provide an existing `token` and optionally `refresh_token` to skip the login step.

The `brand` field defaults to `"bosch"` — use `"buderus"` for Buderus-branded devices.

## Usage

See [example.py](example.py) for a full working example.

## Error handling

| Exception | Raised when |
|---|---|
| `AuthFailedError` | OAuth2 authentication fails |
| `ApiError` | API returns an error response |
| `NotRespondingError` | Device does not respond (retried up to 5 times with exponential backoff) |
| `InvalidSensorDataError` | Sensor data cannot be parsed |

All exceptions inherit from `BhcError`.

## Development

[uv](https://docs.astral.sh/uv/) is required. Install it once, then:

```bash
git clone https://github.com/serbanb11/homecom_alt.git
cd homecom_alt
uv sync --group dev
uv run pre-commit install
```

Run the checks:

```bash
uv run pytest --timeout=30 --cov=homecom_alt tests/   # tests
uv run ruff check . && uv run ruff format --check .   # lint
uv run mypy homecom_alt                               # types
```

## License

MIT
