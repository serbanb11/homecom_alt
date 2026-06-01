# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

homecom_alt is an async Python wrapper for controlling Bosch Thermotechnology devices managed by the HomeCom Easy APP. It communicates with the `pointt-api.bosch-thermotechnology.com` REST API using OAuth2 (SingleKey ID) authentication.

Requires Python >= 3.12. Runtime dependencies: `aiohttp`, `tenacity`, `PyJWT`.

## Virtual Environment

**Always use `uv run` to execute tools.** This automatically uses the project virtualenv. Run `uv sync --group dev` once to install all dependencies.

## Common Commands

### Testing
```bash
uv run pytest --timeout=30 --cov=homecom_alt tests/  # Run tests with coverage
uv run pytest --timeout=30 --cov=homecom_alt --python 3.12 tests/  # Run on Python 3.12
uv run pytest --timeout=30 --cov=homecom_alt --python 3.13 tests/  # Run on Python 3.13
uv run pytest tests/test_init.py::TestClassName::test_method  # Run a single test
```

### Linting & Formatting
```bash
uv run ruff check .              # Lint (all rules enabled, see pyproject.toml for ignores)
uv run ruff format .             # Format code
uv run ruff check --fix .        # Auto-fix lint issues
uv run ruff format --check .     # Check formatting without applying changes
```

### Type Checking
```bash
uv run mypy homecom_alt          # Strict mode - all functions must have type hints
```

### Coverage
```bash
uv run coverage report --fail-under=40   # Coverage check (40% minimum threshold)
```

### Run All Checks
```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy homecom_alt && uv run pytest --timeout=30 --cov=homecom_alt tests/ && uv run coverage report --fail-under=40
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
- **Version**: Defined in `pyproject.toml` as `version` under `[project]`.
