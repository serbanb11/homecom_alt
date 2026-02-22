# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

homecom_alt is an async Python wrapper for controlling Bosch Thermotechnology devices managed by the HomeCom Easy APP. It communicates with the `pointt-api.bosch-thermotechnology.com` REST API using OAuth2 (SingleKey ID) authentication.

Requires Python >= 3.12. Runtime dependencies: `aiohttp`, `tenacity`, `PyJWT`.

## Common Commands

### Testing
```bash
tox -e py312              # Run tests on Python 3.12
tox -e py313              # Run tests on Python 3.13
pytest --timeout=30 --cov=homecom_alt tests/  # Run tests directly with coverage
pytest tests/test_init.py::TestClassName::test_method  # Run a single test
```

### Linting & Formatting
```bash
ruff check .              # Lint (all rules enabled, see pyproject.toml for ignores)
ruff format .             # Format code
ruff check --fix .        # Auto-fix lint issues
tox -e lint               # Lint via tox (check + format check)
```

### Type Checking
```bash
mypy homecom_alt          # Strict mode - all functions must have type hints
tox -e typing             # Type check via tox
```

### Coverage
```bash
tox -e coverage           # Coverage check (40% minimum threshold)
```

### Run All Checks
```bash
tox                       # Runs: py312, py313, lint, typing, coverage
```

## Architecture

### Class Hierarchy

All classes are in `homecom_alt/__init__.py`:

```
HomeComAlt          — Base class: OAuth2 auth, HTTP requests, device discovery, retry logic
├── HomeComGeneric  — Simple devices with minimal endpoints
├── HomeComRac      — Air conditioning units (temperature, HVAC mode, fan, plasmacluster)
├── HomeComK40      — HVAC systems (DHW circuits, heating circuits, heat sources, ventilation, consumption)
└── HomeComWddw2    — Domestic hot water devices (temperature levels, sensors, water flow)
```

### Key Files

- `homecom_alt/__init__.py` — All client classes (~2100 lines). Entry point is `HomeComAlt.create()` factory method.
- `homecom_alt/const.py` — API endpoint URL constants (~50+ endpoints)
- `homecom_alt/model.py` — Frozen dataclasses for device data (`BHCDeviceRac`, `BHCDeviceK40`, `BHCDeviceWddw2`, `ConnectionOptions`)
- `homecom_alt/exceptions.py` — Error hierarchy: `BhcError` → `ApiError`, `AuthFailedError`, `NotRespondingError`, `InvalidSensorDataError`
- `example.py` — Full usage example showing auth flow and device interaction

### Request Flow

1. `get_token()` handles OAuth2 token acquisition/refresh (5-minute expiry buffer)
2. `_async_http_request()` makes requests with Bearer auth to the Bosch API
3. Retry decorator (tenacity): up to 5 attempts with exponential backoff on `NotRespondingError`
4. Each device subclass has `async_update()` that gathers all relevant endpoint data into a frozen dataclass
5. 404 responses are treated as unsupported endpoints (not errors)

### Patterns

- **pytest-asyncio strict mode**: Tests use `@pytest.mark.asyncio(loop_scope="function")` and mock HTTP with `aioresponses`
- **Consumption data**: Uses POST to `/pointt-api/api/v1/bulk` endpoint for recording queries
- **Dynamic circuit discovery**: Circuit IDs are parsed from API response paths
- **Endpoint fallbacks**: Some methods try alternative endpoint paths (e.g., `async_get_time()` tries DateTime then dateTime)

## Code Quality Rules

- **Ruff**: All rules enabled (`select = ["ALL"]`), target Python 3.13. Max complexity 25.
- **MyPy**: Strict mode — all functions require complete type annotations.
- **Version**: Defined in `setup.py` as `VERSION` constant.
