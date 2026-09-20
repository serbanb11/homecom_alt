"""Client for the Bosch K 40 RF Local API (LAN, read-only).

Documented at https://github.com/bosch-home-comfort/api-docs and verified
against a K 40 RF on firmware 15.00.01 driving a Compress CS5800iAW 12.

Three things about this API shape the code below:

* **It is read-only.** Every resource reports ``writeable: 0`` and the
  specification documents ``GET`` only, so every control path stays on the cloud
  client. This module deliberately offers no write method.
* **Two ports.** Tokens are created, listed and revoked on
  :data:`LOCAL_AUTH_PORT`; resources are read on :data:`LOCAL_API_PORT`. A
  successful token request says nothing about connectivity to the resource port.
* **TLS cannot be verified.** The gateway presents a certificate whose CN is the
  device identifier (e.g. ``CN=102128202``) rather than its mDNS hostname or IP,
  so hostname verification fails by construction. ``ssl=False`` below is
  therefore the only option, not a shortcut -- please do not "fix" it. The
  connection is still encrypted; use it on a trusted network only.

One observed behaviour is worth repeating because it looks like a network fault:
**the resource port does not listen until at least one token exists.** Before the
first token, connections to :data:`LOCAL_API_PORT` time out while
:data:`LOCAL_AUTH_PORT` answers normally. The gateway also drops traffic to every
closed port, so probing cannot distinguish "not listening" from "filtered".
Treat "auth port reachable, resource port not" as *unprovisioned*, not as a
firewall problem.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from aiohttp import (
    ClientConnectorError,
    ClientError,
    ClientResponseError,
    Fingerprint,
)
from tenacity import (
    after_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_incrementing,
)

from .const import (
    LOCAL_API_PORT,
    LOCAL_AUTH_PORT,
    LOCAL_DHW_STATUS_TO_MODE,
    LOCAL_ENDPOINT_REVOKE,
    LOCAL_ENDPOINT_TOKEN,
    LOCAL_MAX_CONCURRENT,
    LOCAL_POLL_RESOURCES,
    LOCAL_SAMPLE_RATES,
    LOCAL_TIMEOUT,
    LOCAL_UNSUPPORTED_TTL,
    LOCAL_UPDATE_BUDGET,
)
from .exceptions import (
    ApiError,
    AuthFailedError,
    NotRespondingError,
    ProximityRequiredError,
    TokenStoreFullError,
)
from .model import BHCDeviceK40Local

if TYPE_CHECKING:
    from collections.abc import Sequence

    from aiohttp import ClientSession

_LOGGER = logging.getLogger(__name__)

# The gateway answers 412 while proximity is unproven and 507 when its token
# store is full. Both are actionable by the user, so they get their own
# exceptions rather than a generic ApiError.
_HTTP_PROXIMITY_REQUIRED = 412
_HTTP_INSUFFICIENT_STORAGE = 507

# Statuses that mean "this appliance does not have that resource". Tolerated on
# reads and remembered for LOCAL_UNSUPPORTED_TTL.
_UNSUPPORTED_STATUSES = frozenset(
    {HTTPStatus.FORBIDDEN.value, HTTPStatus.NOT_FOUND.value}
)

_DHW_STATUS_RESOURCE = "/dhwCircuits/dhw1/overallStatus"
_HC_STATUS_RESOURCE = "/heatingCircuits/hc1/overallStatus"
_FIRMWARE_RESOURCE = "/gateway/versionFirmware"


class HomeComK40Local:
    """Read a K 40 RF gateway over the local network.

    The client is cheap to construct and holds no connection of its own; pass in
    the shared :class:`aiohttp.ClientSession`.
    """

    def __init__(
        self,
        session: ClientSession,
        host: str,
        token: str | None = None,
        *,
        device_id: str | None = None,
        fingerprint: bytes | None = None,
    ) -> None:
        """Initialize.

        ``host`` is a hostname or IP without scheme or port. ``token`` is the
        never-expiring access token from :meth:`async_create_token`; it may be
        omitted while provisioning.

        ``fingerprint`` is the SHA-256 digest of the gateway's certificate. The
        certificate cannot be verified by hostname (see the module docstring),
        but it can be *pinned*: with a fingerprint every request refuses a
        gateway presenting a different certificate, which restores protection
        against someone on the LAN impersonating it to collect the token.
        Without one, requests are encrypted but unauthenticated, as before.
        """
        self._session = session
        self._host = host
        self._token = token
        self._device_id = device_id
        self._ssl: Fingerprint | bool = (
            Fingerprint(fingerprint) if fingerprint is not None else False
        )
        self._semaphore = asyncio.Semaphore(LOCAL_MAX_CONCURRENT)
        # Paths this appliance answered 404/403 for -> when (monotonic).
        self._unsupported: dict[str, float] = {}

    @property
    def host(self) -> str:
        """Return the gateway host."""
        return self._host

    @property
    def token(self) -> str | None:
        """Return the access token."""
        return self._token

    @token.setter
    def token(self, value: str) -> None:
        """Set the access token."""
        self._token = value

    @property
    def unsupported(self) -> tuple[str, ...]:
        """Return the resource paths currently remembered as absent."""
        return tuple(sorted(p for p in self._unsupported if self._is_unsupported(p)))

    def _is_unsupported(self, path: str) -> bool:
        """Whether ``path`` answered 404/403 within LOCAL_UNSUPPORTED_TTL."""
        seen = self._unsupported.get(path)
        return seen is not None and time.monotonic() - seen < LOCAL_UNSUPPORTED_TTL

    def _auth_url(self, endpoint: str) -> str:
        return f"https://{self._host}:{LOCAL_AUTH_PORT}{endpoint}"

    def _api_url(self, path: str) -> str:
        return f"https://{self._host}:{LOCAL_API_PORT}{path}"

    async def _request(
        self,
        method: str,
        url: str,
        *,
        data: Any | None = None,
        authenticated: bool = True,
    ) -> Any:
        """Perform one request and return the parsed JSON body.

        Returns ``None`` for the tolerated "resource absent" statuses so callers
        can treat them as missing rather than failing.
        """
        headers: dict[str, str] = {}
        if authenticated:
            if not self._token:
                raise AuthFailedError("No local access token")
            headers["Authorization"] = f"Bearer {self._token}"
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            _LOGGER.debug("Requesting %s, method: %s", url, method)
            resp = await self._session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout=LOCAL_TIMEOUT,
                raise_for_status=True,
                # See the module docstring: the certificate carries a device
                # identifier instead of the hostname, so verification can never
                # succeed. Do not change this to True; pin a fingerprint
                # instead (see __init__).
                ssl=self._ssl,
            )
        except ClientResponseError as error:
            self._raise_for_response_error(error, url)
            return None
        except (TimeoutError, ClientConnectorError) as error:
            raise NotRespondingError(f"{url} is not responding") from error
        except ClientError as error:
            raise ApiError(f"Request to {url} failed: {error}") from error

        if resp.status == HTTPStatus.NO_CONTENT.value:
            return None
        try:
            return await resp.json()
        except (ValueError, ClientError) as error:
            raise ApiError(f"Invalid JSON from {url}") from error

    @staticmethod
    def _raise_for_response_error(error: ClientResponseError, url: str) -> None:
        """Translate an HTTP error status into the right exception.

        Returns normally for the statuses that mean "this appliance does not have
        that resource", which the caller reports as a missing value.
        """
        status = error.status
        if status == HTTPStatus.UNAUTHORIZED.value:
            raise AuthFailedError("Local access token was rejected") from error
        if status == _HTTP_PROXIMITY_REQUIRED:
            raise ProximityRequiredError(
                "Gateway requires a physical button press before issuing a token"
            ) from error
        if status == _HTTP_INSUFFICIENT_STORAGE:
            raise TokenStoreFullError(
                "Gateway token store is full; revoke an unused token"
            ) from error
        if status in _UNSUPPORTED_STATUSES:
            _LOGGER.debug("Resource %s returned %s", url, status)
            return
        if status in (HTTPStatus.BAD_GATEWAY.value, HTTPStatus.GATEWAY_TIMEOUT.value):
            raise NotRespondingError(f"{url} returned {status}") from error
        raise ApiError(f"Invalid response from {url}: {status}") from error

    async def async_get_certificate_fingerprint(self) -> bytes:
        """Return the SHA-256 digest of the certificate the gateway presents.

        For trust on first use: read it once while provisioning -- when the user
        is standing at the gateway pressing its buttons -- store it, and pass it
        back as ``fingerprint`` from then on. Read from :data:`LOCAL_AUTH_PORT`,
        the only port that listens before the first token exists.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            async with asyncio.timeout(LOCAL_TIMEOUT.total):
                _, writer = await asyncio.open_connection(
                    self._host, LOCAL_AUTH_PORT, ssl=context
                )
        except (TimeoutError, OSError) as error:
            raise NotRespondingError(
                f"{self._host}:{LOCAL_AUTH_PORT} is not responding"
            ) from error
        try:
            certificate = writer.get_extra_info("ssl_object").getpeercert(
                binary_form=True
            )
        finally:
            writer.close()
        if not certificate:
            raise ApiError("Gateway presented no certificate")
        return hashlib.sha256(certificate).digest()

    # -- token management (LOCAL_AUTH_PORT) ---------------------------------

    async def async_create_token(
        self, login: str, password: str, client_name: str
    ) -> dict:
        """Create an access token.

        ``login`` and ``password`` are the ``Login`` and ``Pass`` values printed
        on the gateway label; any hyphens in ``password`` are stripped here
        because the gateway expects it without them.

        Requires the WLAN and Wireless buttons to have been pressed together
        within the preceding five minutes, otherwise the gateway answers 412 and
        this raises :class:`ProximityRequiredError`.

        The returned token does not expire. Store it like a password. On success
        the token is also applied to this client.
        """
        payload = {
            "grant_type": "password",
            "username": login,
            "password": password.replace("-", ""),
            "client_name": client_name,
        }
        response = await self._request(
            "post",
            self._auth_url(LOCAL_ENDPOINT_TOKEN),
            data=payload,
            authenticated=False,
        )
        if not isinstance(response, dict) or "access_token" not in response:
            raise ApiError("Token response did not contain an access token")
        self._token = response["access_token"]
        return response

    async def async_list_tokens(self) -> list[dict]:
        """List the tokens the gateway currently holds.

        Note that ``created_at`` is an ISO-8601 string on firmware 15.00.01 even
        though the published example shows an epoch integer, so do not assume a
        numeric type.
        """
        response = await self._request("get", self._auth_url(LOCAL_ENDPOINT_TOKEN))
        if not isinstance(response, list):
            raise ApiError("Unexpected token list response")
        return response

    async def async_revoke_token(
        self, token_id: str, usage_type: str = "private"
    ) -> None:
        """Revoke a token by its ``token_id`` from :meth:`async_list_tokens`."""
        await self._request(
            "post",
            self._auth_url(LOCAL_ENDPOINT_REVOKE),
            data={"token_id": token_id, "usage_type": usage_type},
        )

    # -- resource reads (LOCAL_API_PORT) ------------------------------------

    async def async_get_resource(self, path: str) -> dict | None:
        """Read one resource, or return ``None`` if this appliance lacks it.

        Paths that answered 404/403 within :data:`LOCAL_UNSUPPORTED_TTL` are
        skipped without a request.
        """
        if self._is_unsupported(path):
            _LOGGER.debug("Skipping unsupported resource %s", path)
            return None
        response = await self._request("get", self._api_url(path))
        if response is None:
            self._unsupported[path] = time.monotonic()
            return None
        self._unsupported.pop(path, None)
        if not isinstance(response, dict):
            raise ApiError(f"Unexpected payload for {path}")
        return response

    async def async_get_resources(self, paths: Sequence[str]) -> dict[str, dict]:
        """Read several resources concurrently, capped at two in flight.

        Absent resources are omitted from the result rather than mapped to
        ``None``, so a caller can tell "not supported" from "no value".

        Fails fast: the first transport error aborts the remaining reads. A
        gateway either answers on the LAN or it does not, so working through
        dozens of individual timeouts would only delay the inevitable -- with the
        default poll set that took minutes before this was added.
        """
        # An explicit flag rather than relying on gather's cancellation: tasks
        # already queued behind the semaphore would otherwise each issue their
        # own doomed request before the cancellation reaches them.
        aborted = False

        async def _one(path: str) -> tuple[str, dict | None]:
            nonlocal aborted
            async with self._semaphore:
                if aborted:
                    return path, None
                try:
                    return path, await self.async_get_resource(path)
                except (NotRespondingError, AuthFailedError):
                    aborted = True
                    raise

        tasks = [asyncio.create_task(_one(p)) for p in paths]
        try:
            results = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return {path: payload for path, payload in results if payload is not None}

    async def async_get_recording(
        self,
        path: str,
        sample_rate: str,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict | None:
        """Read a ``/recordings/**`` resource.

        ``sample_rate`` must be one of :data:`LOCAL_SAMPLE_RATES` -- these are
        exact, case-sensitive ISO-8601 duration tokens and the gateway rejects
        anything else with 400.

        Value semantics differ by resource and are easy to get wrong: for
        temperatures each bucket's ``y`` is a **sum** over ``c`` samples, so the
        mean is ``y / c``; for energy ``y`` is already the bucket total.
        """
        if sample_rate not in LOCAL_SAMPLE_RATES:
            raise ApiError(
                f"Invalid sample rate {sample_rate!r}; expected one of "
                f"{', '.join(LOCAL_SAMPLE_RATES)}"
            )
        query = f"?sampleRate={sample_rate}"
        if start_date:
            query += f"&startDate={start_date}"
        if end_date:
            query += f"&endDate={end_date}"
        response = await self._request("get", self._api_url(f"{path}{query}"))
        if response is not None and not isinstance(response, dict):
            raise ApiError(f"Unexpected recording payload for {path}")
        return response

    @retry(
        retry=retry_if_exception_type(NotRespondingError),
        stop=stop_after_attempt(2),
        wait=wait_incrementing(start=1, increment=1),
        after=after_log(_LOGGER, logging.DEBUG),
        # Surface the underlying NotRespondingError rather than tenacity's
        # RetryError, so callers can handle one exception type.
        reraise=True,
    )
    async def async_update(self) -> BHCDeviceK40Local:
        """Read the full local poll set and return it.

        Bounded by :data:`LOCAL_UPDATE_BUDGET` so an unreachable gateway can
        never stall a consumer's update cycle. Retried once, because a second
        attempt is cheap on a LAN; a rejected token is not retried, since it will
        not start working.
        """
        try:
            async with asyncio.timeout(LOCAL_UPDATE_BUDGET):
                resources = await self.async_get_resources(LOCAL_POLL_RESOURCES)
        except TimeoutError as error:
            raise NotRespondingError(
                f"Local update exceeded {LOCAL_UPDATE_BUDGET}s"
            ) from error
        if not resources:
            raise ApiError("Local gateway returned no resources")

        return BHCDeviceK40Local(
            device=self._device_id,
            firmware=_value(resources.get(_FIRMWARE_RESOURCE)),
            resources=resources,
            unsupported=self.unsupported,
            dhw_mode=self.dhw_mode(resources),
            hc_status=_value(resources.get(_HC_STATUS_RESOURCE)),
        )

    @staticmethod
    def dhw_mode(resources: dict[str, dict]) -> str | None:
        """Derive the cloud-style DHW operation mode from ``overallStatus``.

        The Local API has no ``operationMode`` resource, so the mode has to come
        from ``overallStatus``. Returns ``None`` when the appliance is in a state
        that has no mode equivalent (``away``, ``holiday``, ``extra``, ``td``,
        ``floor_drying``, ``dhw_disabled``) -- callers must not read that as off.

        Note that ``overallStatus`` is the slowest of the DHW resources to follow
        a change: it was observed lagging ``currentTemperatureLevel`` by up to
        24 s. Prefer ``currentTemperatureLevel`` when freshness matters more than
        distinguishing manual from scheduled operation.
        """
        status = _value(resources.get(_DHW_STATUS_RESOURCE))
        if status is None:
            return None
        return LOCAL_DHW_STATUS_TO_MODE.get(status)


def _value(payload: dict | None) -> Any | None:
    """Return a resource payload's ``value``, or ``None`` if absent."""
    if not isinstance(payload, dict):
        return None
    return payload.get("value")
