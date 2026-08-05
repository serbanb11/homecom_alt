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

Three channels live under ``users/{sub}/devices/{serial}/``, and only the first is
request/response:

* ``shadows/{state,schedule}/…`` — the shadow above. Not retained: nothing arrives
  until a ``get`` is published or the device reports a change.
* ``topics/{sensor,meta,info}`` — **push only**. No request verb exists anywhere in
  the app, so these cannot be polled; the device publishes on its own cadence
  (``dataLakeBasePublishInterval``, 1800 s in the wild). ``sensor`` is the only
  source of live readings such as ``roomTemperature`` — it is *not* in the shadow.
* ``commands/{export,force_schedule,reset_matter}`` — outbound actions.

The single ``users/{sub}/#`` subscription already covers all three, so every
payload is cached as it arrives (see :meth:`BaconMqttClient.raw_snapshot`).
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
from contextlib import suppress
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, NamedTuple

import paho.mqtt.client as mqtt

from .const import (
    BACON_DEFAULT_REGION,
    BACON_HOST_TEMPLATE,
    BACON_MQTT_PORT,
    BACON_RAC_TYPE,
    BACON_USER_AGENT,
    BACON_WS_PATH,
)
from .exceptions import ApiError, AuthFailedError, MqttNotAuthorizedError

if TYPE_CHECKING:
    from aiohttp import ClientSession

_LOGGER = logging.getLogger(__name__)

# users/{sub}/devices/{serial}/{channel}/{rest…} — index of each field.
_TOPIC_USERS = 0
_TOPIC_SUB = 1
_TOPIC_SCOPE = 2
_TOPIC_SERIAL = 3
_TOPIC_CHANNEL = 4
_TOPIC_MIN_PARTS = 5
# users/{sub}/{channel}[/…] — the shortest topic still worth dispatching on.
_ACCOUNT_TOPIC_MIN_PARTS = 3

# Push-only channel: the subtopics whose latest payload is worth keeping.
_TOPICS_CHANNEL = "topics"
_TOPIC_SENSOR = "sensor"
_TOPIC_META = "meta"
_TOPIC_INFO = "info"

# Cap a single cached payload. ``schedules`` arrives gzip+base64 and a handful of
# devices would otherwise dominate a diagnostics dump.
_MAX_CACHED_PAYLOAD_CHARS = 20_000

_CREDENTIAL_REASON_CODES = frozenset({4, 5, 134, 135})
_CREDENTIAL_REASON_NAMES = frozenset(
    {"bad user name or password", "not authorized", "not authorised"}
)

ShadowListener = Callable[[dict[str, Any]], None]

#: ``(serial, channel_path, payload)`` for every message seen on the wildcard.
#: ``serial`` is ``None`` for account-level topics such as ``users/{sub}/commands/x``.
RawListener = Callable[[str | None, str, Any], None]


class ParsedTopic(NamedTuple):
    """A bacon topic split into the parts callers actually dispatch on."""

    serial: str | None
    """Device serial, or ``None`` for an account-level topic."""

    channel: str
    """``shadows``, ``topics``, ``commands`` — or ``""`` if unrecognised."""

    path: str
    """Everything after the channel, e.g. ``state/get/accepted`` or ``sensor``."""

    @property
    def channel_path(self) -> str:
        """``channel/path``, the key a message is cached and dispatched under.

        Includes the channel so ``topics/sensor`` can never collide with a
        same-named subtopic of ``shadows`` or ``commands``.
        """
        return f"{self.channel}/{self.path}" if self.path else self.channel


def parse_topic(topic: str) -> ParsedTopic | None:
    """Split a bacon MQTT topic, or return ``None`` if it is not one.

    Handles both the device form ``users/{sub}/devices/{serial}/{channel}/{rest}``
    and the account form ``users/{sub}/{channel}/{rest}`` (used by
    ``users/{sub}/commands/{command}``), so a subscription to ``users/{sub}/#``
    can be demultiplexed without raising on the shorter shape.
    """
    parts = topic.split("/")
    if len(parts) < _ACCOUNT_TOPIC_MIN_PARTS or parts[_TOPIC_USERS] != "users":
        return None
    is_device = len(parts) >= _TOPIC_MIN_PARTS and parts[_TOPIC_SCOPE] == "devices"
    if is_device:
        return ParsedTopic(
            parts[_TOPIC_SERIAL],
            parts[_TOPIC_CHANNEL],
            "/".join(parts[_TOPIC_CHANNEL + 1 :]),
        )
    # Account-level: users/{sub}/{channel}/{rest…}
    return ParsedTopic(None, parts[_TOPIC_SCOPE], "/".join(parts[_TOPIC_SCOPE + 1 :]))


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Return the decoded payload of a JWT, or ``None`` if unparsable.

    The signature is not verified — these claims are only used to address the
    broker (``sub``) and to schedule a reconnect before the token expires.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def decode_jwt_sub(token: str) -> str | None:
    """Return the ``sub`` claim of a JWT access token, or ``None`` if unparsable."""
    payload = _decode_jwt_payload(token)
    if payload is None:
        return None
    sub = payload.get("sub")
    return str(sub) if sub is not None else None


def decode_jwt_exp(token: str) -> datetime | None:
    """Return the ``exp`` claim of a JWT access token as an aware UTC datetime."""
    payload = _decode_jwt_payload(token)
    if payload is None:
        return None
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return None
    try:
        return datetime.fromtimestamp(exp, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _is_credential_refusal(reason_code: Any) -> bool:
    """Return whether a refused CONNACK means the credentials were rejected.

    Covers MQTT 5 ``Bad user name or password`` (0x86) and ``Not authorized``
    (0x87) plus the MQTT 3.1.1 equivalents, by numeric code and by name.
    """
    value = getattr(reason_code, "value", reason_code)
    if isinstance(value, int) and value in _CREDENTIAL_REASON_CODES:
        return True
    return str(reason_code).strip().lower() in _CREDENTIAL_REASON_NAMES


def _refusal_error(reason_code: Any) -> ApiError:
    """Map a refused CONNACK reason code onto the exception to raise.

    A credential refusal becomes :class:`MqttNotAuthorizedError` — a transport
    failure the caller fixes by reconnecting with a rotated access token — and
    never :class:`AuthFailedError`, which would be read as a dead OAuth refresh
    token and trigger a pointless re-authentication.
    """
    message = f"Bacon MQTT connect refused: {reason_code}"
    if _is_credential_refusal(reason_code):
        return MqttNotAuthorizedError(message)
    return ApiError(message)


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

    Reconnection is owned by the **caller**, not by paho: the MQTT password is
    the access token, so paho's automatic reconnect would keep re-presenting a
    credential the broker has already refused. See :meth:`token_expires_at` for
    scheduling a reconnect before that happens.
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
        self._token: str | None = None
        self._connected = asyncio.Event()
        self._connect_done = asyncio.Event()
        self._connect_rc: Any = None
        self._get_futures: dict[str, asyncio.Future] = {}
        self._listeners: dict[str, list[ShadowListener]] = {}
        self._raw_listeners: list[RawListener] = []
        # (serial, channel_path) -> {"payload": ..., "received_at": ...}. One
        # entry per key: only the newest payload of each topic is of interest,
        # and for a push-only channel its age matters as much as its content.
        self._raw: dict[tuple[str | None, str], dict[str, Any]] = {}

    @property
    def client_id(self) -> str:
        """Return the MQTT client id (persist this to keep it stable)."""
        return self._client_id

    @property
    def is_connected(self) -> bool:
        """Return whether the MQTT session is currently up."""
        return self._connected.is_set()

    @property
    def token_expires_at(self) -> datetime | None:
        """Return when the token of the current session expires (UTC).

        ``None`` if no token has been presented yet or it carries no usable
        ``exp`` claim. The broker keeps the session only as long as the access
        token it was opened with is valid, so a caller wanting an uninterrupted
        session must reconnect with a fresh token before this moment.
        """
        return decode_jwt_exp(self._token) if self._token else None

    def register_listener(self, serial: str, callback: ShadowListener) -> None:
        """Register a callback invoked (on the asyncio loop) on shadow updates."""
        self._listeners.setdefault(serial, []).append(callback)

    def register_raw_listener(self, callback: RawListener) -> None:
        """Register a callback invoked (on the asyncio loop) for *every* message.

        Called as ``callback(serial, channel_path, payload)``. Intended for
        diagnostics and for capturing channels this library does not model yet;
        :meth:`register_listener` remains the way to follow a device's shadow.
        """
        self._raw_listeners.append(callback)

    def remove_raw_listener(self, callback: RawListener) -> None:
        """Unregister a raw listener. Silent if it was never registered.

        Lets a caller capture over a bounded window without leaking a callback
        when the window ends — or when it ends by being cancelled.
        """
        with suppress(ValueError):
            self._raw_listeners.remove(callback)

    def raw_snapshot(self) -> dict[str, dict[str, Any]]:
        """Return every cached payload, keyed ``"{serial}/{channel_path}"``.

        JSON-serialisable, for a diagnostics dump. Each value is
        ``{"payload": ..., "received_at": <ISO 8601>}``. Account-level topics use
        ``"-"`` in place of a serial.

        The caller is responsible for redaction: the ``users/{sub}/#``
        subscription also carries other devices on the account and the
        sharing/claim traffic, and ``topics/info`` includes Matter onboarding
        secrets.
        """
        return {
            f"{serial or '-'}/{path}": {
                "payload": entry["payload"],
                "received_at": entry["received_at"].isoformat(),
            }
            for (serial, path), entry in sorted(
                self._raw.items(), key=lambda item: (item[0][0] or "", item[0][1])
            )
        }

    def get_topic(self, serial: str, subtopic: str) -> Any | None:
        """Return the last payload cached for ``topics/{subtopic}`` of ``serial``.

        A pure cache read. ``topics/*`` is **push only** — there is no request
        verb for it anywhere in the protocol — so this returns ``None`` until the
        device has published, and must never be turned into a publish.
        """
        entry = self._raw.get((serial, f"{_TOPICS_CHANNEL}/{subtopic}"))
        return entry["payload"] if entry else None

    def get_sensor(self, serial: str) -> dict[str, Any] | None:
        """Return the newest ``topics/sensor`` reading for ``serial``.

        The payload is ``{"deviceType": …, "items": [ … ]}``; the last item is
        returned, which for a RAC carries ``roomTemperature`` — the live room
        temperature that is absent from the shadow. ``None`` if nothing has been
        published yet (expect up to ``dataLakeBasePublishInterval`` of silence,
        and nothing at all straight after a reconnect).
        """
        payload = self.get_topic(serial, _TOPIC_SENSOR)
        if not isinstance(payload, dict):
            return None
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            return None
        latest = items[-1]
        return latest if isinstance(latest, dict) else None

    def get_metadata(self, serial: str) -> dict[str, Any] | None:
        """Return the newest ``topics/meta`` payload for ``serial``.

        Typed capability metadata: string fields carry ``{"enum": [...]}``, float
        fields ``{"min": …, "max": …, "unit": …}``, all of them ``"ro"``. Lets a
        caller derive a device's real modes and bounds instead of hardcoding them.
        """
        payload = self.get_topic(serial, _TOPIC_META)
        return payload if isinstance(payload, dict) else None

    def get_info(self, serial: str) -> dict[str, Any] | None:
        """Return the newest ``topics/info`` payload for ``serial``.

        Identity and health: ``online``, ``firmwareVersion``, ``hardwareVersion``,
        ``signalStrength``, ``displayCode``, ``errorClass`` — plus Matter
        commissioning fields, which are secrets and must not be logged.
        """
        payload = self.get_topic(serial, _TOPIC_INFO)
        return payload if isinstance(payload, dict) else None

    async def async_connect(self, token: str, sub: str) -> None:
        """(Re)connect to the broker with a fresh token. Idempotent.

        Raises :class:`MqttNotAuthorizedError` when the broker refuses the
        credentials (i.e. the access token has expired) and :class:`ApiError` for
        any other refusal or a timeout.
        """
        self._loop = asyncio.get_running_loop()
        self._sub = sub
        self._token = token
        await self.async_disconnect()

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self._client_id,
            protocol=mqtt.MQTTv5,
            transport="websockets",
            # Never let paho re-dial on its own: the stored password is the
            # access token, so an automatic retry would replay a credential the
            # broker has already refused, producing "Not authorized" bursts.
            reconnect_on_failure=False,
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
        self._connect_done.clear()
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
            await asyncio.wait_for(self._connect_done.wait(), timeout=15)
        except TimeoutError as err:
            reason_code = self._connect_rc
            await self.async_disconnect()
            if reason_code in (0, None):
                raise ApiError("Timed out connecting to bacon MQTT broker") from err
            raise _refusal_error(reason_code) from err
        if self._connected.is_set():
            return
        # CONNACK arrived but was a refusal; _on_connect woke us straight away.
        reason_code = self._connect_rc
        await self.async_disconnect()
        raise _refusal_error(reason_code)

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
            # Wake async_connect now instead of leaving it to time out: it
            # classifies the reason code and reports a transport-credential
            # refusal separately from any other failure. Auto-reconnect is off,
            # so paho's network thread simply winds down after this.
            self._signal_connect_done()
            return
        # The app subscribes to the whole user namespace; do the same so any
        # device's shadow get/update replies are delivered. The broker uses clean
        # start, so this has to be re-issued on every (re)connect.
        client.subscribe(f"users/{self._sub}/#")
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._connected.set)
        self._signal_connect_done()

    def _signal_connect_done(self) -> None:
        """Tell a waiting :meth:`async_connect` that the CONNACK has landed."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._connect_done.set)

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
        parsed = parse_topic(topic)
        if parsed is None:
            return
        try:
            payload = json.loads(msg.payload.decode()) if msg.payload else {}
        except (ValueError, UnicodeDecodeError):
            # Keep the undecodable body: knowing a topic fired, and roughly what
            # it carried, is worth more than dropping it silently.
            payload = self._undecodable_payload(msg.payload)

        self._cache_raw(parsed, payload)
        self._notify_raw(parsed, payload)

        if parsed.channel == "shadows" and parsed.serial is not None:
            self._handle_shadow(parsed.serial, topic, payload)

    def _handle_shadow(self, serial: str, topic: str, payload: Any) -> None:
        """Resolve a pending get and fan a shadow change out to its listeners."""
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

    @staticmethod
    def _undecodable_payload(raw: bytes) -> dict[str, str]:
        """Describe a body that is not JSON, without letting it grow unbounded."""
        text = raw.decode(errors="replace")[:_MAX_CACHED_PAYLOAD_CHARS]
        return {"__raw__": text}

    def _cache_raw(self, parsed: ParsedTopic, payload: Any) -> None:
        """Keep the newest payload per topic, size-capped."""
        self._raw[parsed.serial, parsed.channel_path] = {
            "payload": self._cap(payload),
            "received_at": datetime.now(UTC),
        }

    @classmethod
    def _cap(cls, payload: Any) -> Any:
        """Replace an oversized payload with a marker of its size.

        ``schedules`` is gzip+base64 and a few devices would otherwise dominate a
        diagnostics dump.
        """
        if isinstance(payload, str) and len(payload) > _MAX_CACHED_PAYLOAD_CHARS:
            return {"__truncated__": len(payload)}
        if isinstance(payload, dict):
            return {key: cls._cap(value) for key, value in payload.items()}
        if isinstance(payload, list):
            return [cls._cap(item) for item in payload]
        return payload

    def _notify_raw(self, parsed: ParsedTopic, payload: Any) -> None:
        """Hand every message to the raw listeners, on the asyncio loop."""
        if self._loop is None:
            return
        for callback in self._raw_listeners:
            self._loop.call_soon_threadsafe(
                callback, parsed.serial, parsed.channel_path, payload
            )

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

    @property
    def sensor(self) -> dict[str, Any] | None:
        """Latest ``topics/sensor`` reading, e.g. ``{"roomTemperature": 24.5}``.

        ``None`` until the device pushes one — this channel cannot be polled.
        """
        return self._client.get_sensor(self.device_id)

    @property
    def metadata(self) -> dict[str, Any] | None:
        """Latest ``topics/meta`` payload (capability metadata), if seen."""
        return self._client.get_metadata(self.device_id)

    @property
    def info(self) -> dict[str, Any] | None:
        """Latest ``topics/info`` payload (identity and health), if seen."""
        return self._client.get_info(self.device_id)

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
