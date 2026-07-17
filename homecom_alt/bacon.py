"""Support for Bosch HomeCom Matter/"Bacon"-commissioned RAC air conditioners.

These units (serial numbers like ``86DM-580-...``) are commissioned through the
HomeCom Easy app over Matter and are managed by Bosch's *bacon* backend. They do
**not** appear in the classic pointt ``/gateways/`` listing, so the REST device
classes in this library never see them. Instead they are read and controlled via
an AWS-IoT-style **device shadow** exposed over MQTT 5 (WebSocket).

Protocol (reverse-engineered from HomeCom Easy 4.0.0, verified live):

* Broker ``wss://broker.euc1.bacon.bosch-tt-cw.com:443/mqtt`` (MQTT v5, ws
  subprotocol ``mqtt``).
* ClientID must be a 64-char lowercase hex string, otherwise CONNACK is refused.
* WebSocket upgrade headers: ``Authorization: Bearer <token>`` and a ``User-Agent``.
* MQTT CONNECT: username = JWT ``sub`` claim, password = the raw access token.
* State read: publish empty to ``users/{sub}/devices/{serial}/shadows/state/get`` and
  read the reply on ``.../get/accepted``.
* Control: publish ``{"state": {"desired": {...}}}`` to ``.../shadows/state/update``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import ssl
from collections.abc import Callable
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

import paho.mqtt.client as mqtt

from .const import (
    BACON_DEFAULT_REGION,
    BACON_HOST_TEMPLATE,
    BACON_MQTT_PORT,
    BACON_RAC_TYPE,
    BACON_USER_AGENT,
    BACON_WS_PATH,
)
from .exceptions import ApiError, AuthFailedError

if TYPE_CHECKING:
    from aiohttp import ClientSession

_LOGGER = logging.getLogger(__name__)

# Minimum path segments in a shadow topic before the device serial is present.
_SHADOW_TOPIC_MIN_PARTS = 5

ShadowListener = Callable[[dict[str, Any]], None]


def decode_jwt_sub(token: str) -> str | None:
    """Return the ``sub`` claim of a JWT access token, or ``None`` if unparsable."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        return None
    sub = payload.get("sub")
    return str(sub) if sub is not None else None


def generate_client_id() -> str:
    """Return a broker-acceptable 64-char hex MQTT client id."""
    return hashlib.sha256(os.urandom(16)).hexdigest()


def bacon_host(service: str, region: str = BACON_DEFAULT_REGION) -> str:
    """Build a bacon backend hostname for ``service`` in ``region``."""
    return BACON_HOST_TEMPLATE.format(service=service, region=region)


async def async_get_bacon_devices(
    session: ClientSession, token: str, region: str = BACON_DEFAULT_REGION
) -> list[dict[str, Any]]:
    """Discover Matter/Bacon-commissioned devices for the logged-in user.

    Returns a list of ``{"deviceId": <serial>, "deviceType": "bacon_rac"}`` dicts,
    mirroring the shape used by :meth:`HomeComAlt.async_get_devices`.
    """
    url = f"https://{bacon_host('claiming', region)}/v1/users/self/devices"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": BACON_USER_AGENT,
    }
    async with session.get(url, headers=headers) as resp:
        if resp.status == HTTPStatus.UNAUTHORIZED:
            raise AuthFailedError("Bacon claim request unauthorized")
        if resp.status != HTTPStatus.OK:
            raise ApiError(f"Bacon claim request failed: {resp.status}")
        serials = await resp.json()
    if not isinstance(serials, list):
        return []
    return [{"deviceId": str(s), "deviceType": BACON_RAC_TYPE} for s in serials]


class BaconMqttClient:
    """Shared MQTT device-shadow client for all bacon devices of a config entry.

    A single connection serves every device; state reads are request/response and
    live changes are pushed to per-serial listeners. paho's network loop runs in
    its own thread; all results are marshalled back onto the asyncio loop that
    called :meth:`async_connect`.
    """

    def __init__(
        self, client_id: str | None = None, region: str = BACON_DEFAULT_REGION
    ) -> None:
        """Initialize the client. ``client_id`` should be stable per HA install."""
        self._client_id = client_id or generate_client_id()
        self._broker_host = bacon_host("broker", region)
        self._client: mqtt.Client | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sub: str | None = None
        self._connected = asyncio.Event()
        self._connect_rc: Any = None
        self._get_futures: dict[str, asyncio.Future] = {}
        self._listeners: dict[str, list[ShadowListener]] = {}

    @property
    def client_id(self) -> str:
        """Return the MQTT client id (persist this to keep it stable)."""
        return self._client_id

    @property
    def is_connected(self) -> bool:
        """Return whether the MQTT session is currently up."""
        return self._connected.is_set()

    def register_listener(self, serial: str, callback: ShadowListener) -> None:
        """Register a callback invoked (on the asyncio loop) on shadow updates."""
        self._listeners.setdefault(serial, []).append(callback)

    async def async_connect(self, token: str, sub: str) -> None:
        """(Re)connect to the broker with a fresh token. Idempotent."""
        self._loop = asyncio.get_running_loop()
        self._sub = sub
        await self.async_disconnect()

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self._client_id,
            protocol=mqtt.MQTTv5,
            transport="websockets",
        )
        client.ws_set_options(
            path=BACON_WS_PATH,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": BACON_USER_AGENT,
            },
        )
        client.username_pw_set(sub, token)
        # Build the SSL context off the event loop: loading the system trust
        # store is blocking I/O (HA flags paho's tls_set() otherwise).
        ssl_context = await self._loop.run_in_executor(None, ssl.create_default_context)
        client.tls_set_context(ssl_context)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        self._client = client
        self._connected.clear()
        self._connect_rc = None

        try:
            await self._loop.run_in_executor(
                None,
                lambda: client.connect(
                    self._broker_host, BACON_MQTT_PORT, keepalive=60
                ),
            )
        except OSError as err:
            raise ApiError(f"Bacon MQTT connect failed: {err}") from err
        client.loop_start()

        try:
            await asyncio.wait_for(self._connected.wait(), timeout=15)
        except TimeoutError as err:
            await self.async_disconnect()
            if self._connect_rc not in (0, None):
                raise AuthFailedError(
                    f"Bacon MQTT connect refused: {self._connect_rc}"
                ) from err
            raise ApiError("Timed out connecting to bacon MQTT broker") from err

    async def async_disconnect(self) -> None:
        """Tear down the current MQTT connection if any."""
        client = self._client
        self._client = None
        self._connected.clear()
        if client is None:
            return

        def _stop() -> None:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:  # noqa: BLE001 - best-effort teardown
                _LOGGER.debug("Ignoring bacon MQTT teardown error", exc_info=True)

        if self._loop is not None:
            await self._loop.run_in_executor(None, _stop)
        else:
            _stop()

    async def async_get_state(
        self,
        serial: str,
        timeout: float = 10.0,  # noqa: ASYNC109 - public API mirrors other device reads
    ) -> dict[str, Any]:
        """Request the current shadow for ``serial`` and await the reply.

        Returns ``{"reported": {...}, "desired": {...}}``.
        """
        if self._client is None:
            raise ApiError("Bacon MQTT client not connected")
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._get_futures[serial] = future
        self._client.publish(self._shadow_topic(serial, "get"), "")
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as err:
            self._get_futures.pop(serial, None)
            raise ApiError(f"Timed out reading shadow for {serial}") from err

    async def async_set_desired(self, serial: str, desired: dict[str, Any]) -> None:
        """Publish a partial ``desired`` shadow update for ``serial``."""
        if self._client is None:
            raise ApiError("Bacon MQTT client not connected")
        payload = json.dumps({"state": {"desired": desired}})
        self._client.publish(self._shadow_topic(serial, "update"), payload)

    def _shadow_topic(self, serial: str, suffix: str) -> str:
        return f"users/{self._sub}/devices/{serial}/shadows/state/{suffix}"

    # -- paho callbacks (run on paho's network thread) --------------------------

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        rc = getattr(reason_code, "value", reason_code)
        self._connect_rc = reason_code
        if str(reason_code) not in ("Success", "0") and rc != 0:
            _LOGGER.error("Bacon MQTT connection refused: %s", reason_code)
            return
        # The app subscribes to the whole user namespace; do the same so any
        # device's shadow get/update replies are delivered.
        client.subscribe(f"users/{self._sub}/#")
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._connected.set)

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        _LOGGER.debug("Bacon MQTT disconnected: %s", reason_code)
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._connected.clear)

    def _on_message(
        self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage
    ) -> None:
        topic = msg.topic
        parts = topic.split("/")
        # users/{sub}/devices/{serial}/shadows/state/{action}[/accepted|/rejected]
        if len(parts) < _SHADOW_TOPIC_MIN_PARTS or parts[2] != "devices":
            return
        serial = parts[3]
        try:
            payload = json.loads(msg.payload.decode()) if msg.payload else {}
        except (ValueError, UnicodeDecodeError):
            return

        if topic.endswith("/get/rejected"):
            self._resolve_get(serial, exc=ApiError(f"Shadow get rejected for {serial}"))
            return

        is_get = topic.endswith("/get/accepted")
        is_update = topic.endswith("/update/accepted")
        if not (is_get or is_update):
            return

        state = payload.get("state", {}) if isinstance(payload, dict) else {}
        result = {
            "reported": state.get("reported", {}) or {},
            "desired": state.get("desired", {}) or {},
        }
        # Only a get/accepted answers a pending read; update/accepted (deltas,
        # keep-alives) must not resolve an in-flight get with partial state.
        if is_get:
            self._resolve_get(serial, result=result)
        for callback in self._listeners.get(serial, []):
            if self._loop is not None:
                self._loop.call_soon_threadsafe(callback, result)

    def _resolve_get(
        self, serial: str, result: dict | None = None, exc: Exception | None = None
    ) -> None:
        future = self._get_futures.pop(serial, None)
        if future is None or self._loop is None or future.done():
            return
        if exc is not None:
            self._loop.call_soon_threadsafe(future.set_exception, exc)
        else:
            self._loop.call_soon_threadsafe(future.set_result, result)


class HomeComBaconRac:
    """Per-device facade over a shared :class:`BaconMqttClient`."""

    def __init__(self, client: BaconMqttClient, serial: str) -> None:
        """Bind a single serial to the shared MQTT client."""
        self._client = client
        self.device_id = serial
        self.device_type = BACON_RAC_TYPE

    async def async_update(self) -> dict[str, Any]:
        """Return the current shadow (``{"reported": ..., "desired": ...}``)."""
        return await self._client.async_get_state(self.device_id)

    async def async_set_power(self, on: bool, mode: str | None = None) -> None:
        """Turn the unit on/off, optionally also setting the operating mode."""
        desired: dict[str, Any] = {"powerEnabled": bool(on)}
        if on and mode:
            desired["opMode"] = mode
        await self._client.async_set_desired(self.device_id, desired)

    async def async_set_mode(self, mode: str) -> None:
        """Set the operating mode (cool/heat/auto/dry/fan)."""
        await self._client.async_set_desired(self.device_id, {"opMode": mode})

    async def async_set_temperature(self, value: int) -> None:
        """Set the target temperature (°C, integer)."""
        await self._client.async_set_desired(
            self.device_id, {"tempSetpoint": int(value)}
        )

    async def async_set_fan(self, fan: str) -> None:
        """Set the fan speed (auto/quiet/low/medium/high/turbo)."""
        await self._client.async_set_desired(self.device_id, {"fanSpeed": fan})

    async def async_set_swing(
        self, horizontal: bool | None = None, vertical: bool | None = None
    ) -> None:
        """Enable/disable horizontal and/or vertical swing."""
        desired: dict[str, Any] = {}
        if horizontal is not None:
            desired["hSwingEnabled"] = bool(horizontal)
        if vertical is not None:
            desired["vSwingEnabled"] = bool(vertical)
        if desired:
            await self._client.async_set_desired(self.device_id, desired)
