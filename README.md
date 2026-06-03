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
