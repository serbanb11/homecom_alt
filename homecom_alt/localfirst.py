"""Local-first update policy for a K40 with the cloud client as fallback.

Why this is a *merge* and not a switch: the K 40 RF Local API is read-only and
does not expose everything the cloud does. It has no ``operationMode`` resource,
no per-level DHW setpoints (``eco``/``low``/``high``/``singleChargeSetpoint``),
and on a system without configured zones no ``/zones/{id}/**`` at all. So the
local transport cannot wholesale replace the cloud for this integration's
current entity set, and pretending otherwise would silently drop entities.

What it *can* do is carry the bulk of the readings, faster and far more
reliably, and keep those readings alive while the cloud is failing -- which is
the actual complaint: when the Bosch cloud returns 504s, cloud-backed entities
go ``unknown``.

This class therefore runs both and reports what it got, leaving the per-field
preference to the caller:

* both succeeded -> :attr:`K40Update.source` is ``"both"``
* only local -> ``"local"``; the cloud-only fields are unavailable this cycle
* only cloud -> ``"cloud"``
* neither -> the cloud error is raised, because that is the one a user can act on

Local failures are counted so a caller can distinguish "one dropped poll" from
"the gateway has gone away", and the count resets on the first success.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tenacity import RetryError

from .exceptions import ApiError, AuthFailedError, BhcError, NotRespondingError

if TYPE_CHECKING:
    from .k40 import HomeComK40
    from .local import HomeComK40Local
    from .model import BHCDeviceK40, BHCDeviceK40Local

_LOGGER = logging.getLogger(__name__)

# Consecutive local failures after which the local transport is reported
# unhealthy. Kept low: the gateway answers in ~50 ms on a LAN, so more than a
# couple of misses in a row means something real, not jitter.
LOCAL_FAILURE_THRESHOLD = 3


# Failures that mean "this transport did not deliver this cycle" rather than a
# bug: they are counted and reported, never raised on their own.
_TRANSPORT_ERRORS = (ApiError, NotRespondingError, RetryError, TimeoutError)


def _as_bhc_error(error: BaseException) -> BhcError:
    """Return ``error`` as a BhcError so callers handle one family."""
    return error if isinstance(error, BhcError) else ApiError(str(error))


async def _skipped() -> None:
    """Stand in for the local read while the local transport is parked."""


@dataclass(frozen=True)
class K40Update:
    """The outcome of one local-first update cycle.

    ``local`` and ``cloud`` are each ``None`` when that transport failed this
    cycle. ``source`` says which produced data. ``local_healthy`` is ``False``
    once the local transport has missed :data:`LOCAL_FAILURE_THRESHOLD` polls in
    a row, which is the signal to stop presenting local-only entities as live.
    """

    local: BHCDeviceK40Local | None
    cloud: BHCDeviceK40 | None
    source: str
    local_healthy: bool
    local_error: str | None = None
    cloud_error: str | None = None


class HomeComK40LocalFirst:
    """Run the local and cloud K40 clients together, preferring local reads."""

    def __init__(
        self,
        local: HomeComK40Local,
        cloud: HomeComK40,
        *,
        failure_threshold: int = LOCAL_FAILURE_THRESHOLD,
    ) -> None:
        """Initialize with an already-configured local and cloud client."""
        self._local = local
        self._cloud = cloud
        self._failure_threshold = failure_threshold
        self._local_failures = 0
        # A token the gateway has rejected will not start working by itself, so
        # once that happens the local transport is parked until reconfigured.
        self._local_disabled = False

    @property
    def local_healthy(self) -> bool:
        """Return whether local reads are currently considered usable."""
        return (
            not self._local_disabled and self._local_failures < self._failure_threshold
        )

    @property
    def local_failures(self) -> int:
        """Return the number of consecutive local failures."""
        return self._local_failures

    @property
    def local_disabled(self) -> bool:
        """Return whether local reads have been parked after an auth failure."""
        return self._local_disabled

    def reset_local(self) -> None:
        """Re-enable local reads, e.g. after a new token has been supplied."""
        self._local_disabled = False
        self._local_failures = 0

    def _record_local(
        self, result: BHCDeviceK40Local | BaseException | None
    ) -> tuple[BHCDeviceK40Local | None, BhcError | None]:
        """Account for one local read and return ``(data, error)``."""
        if isinstance(result, AuthFailedError):
            # Park local reads: retrying a rejected token just produces the
            # same 401 every poll.
            self._local_disabled = True
            _LOGGER.warning(
                "Local gateway rejected the access token; falling back to the "
                "cloud until a new token is provided"
            )
            return None, result
        if isinstance(result, _TRANSPORT_ERRORS):
            self._local_failures += 1
            _LOGGER.debug(
                "Local update failed (%s consecutive): %s",
                self._local_failures,
                result,
            )
            return None, _as_bhc_error(result)
        if isinstance(result, BaseException):
            raise result
        if result is None:
            # Local reads are parked.
            return None, None
        if self._local_failures:
            _LOGGER.info(
                "Local gateway recovered after %s failed attempts",
                self._local_failures,
            )
        self._local_failures = 0
        return result, None

    async def async_update(self, device_id: str) -> K40Update:
        """Update from both transports and report what succeeded.

        Both run concurrently: the local read takes ~2 s and the cloud call can
        take much longer, so serialising them would add the local latency to
        every poll for no benefit.

        Raises the cloud error only when *both* fail -- as long as local data
        came back, the caller has something to show and an outage should not turn
        into an unavailable device.
        """
        # gather(return_exceptions=True) rather than awaiting two tasks in turn:
        # an unexpected error or a cancellation while waiting for the first one
        # used to leave the other running with nobody to collect its result.
        local_result, cloud_result = await asyncio.gather(
            self._local.async_update() if not self._local_disabled else _skipped(),
            self._cloud.async_update(device_id),
            return_exceptions=True,
        )

        local_data, local_error = self._record_local(local_result)

        cloud_data: BHCDeviceK40 | None = None
        cloud_error: BhcError | None = None
        if isinstance(cloud_result, _TRANSPORT_ERRORS):
            cloud_error = _as_bhc_error(cloud_result)
            _LOGGER.debug("Cloud update failed: %s", cloud_result)
        elif isinstance(cloud_result, BaseException):
            # Includes AuthFailedError: cloud auth is the caller's whole reason
            # for existing, so it is never masked.
            raise cloud_result
        else:
            cloud_data = cloud_result

        if local_data is None and cloud_data is None:
            raise cloud_error or local_error or ApiError("Both transports failed")

        if local_data is not None and cloud_data is not None:
            source = "both"
        elif local_data is not None:
            source = "local"
        else:
            source = "cloud"

        if source == "local":
            _LOGGER.info(
                "Cloud update failed; serving this cycle from the local gateway"
            )

        return K40Update(
            local=local_data,
            cloud=cloud_data,
            source=source,
            local_healthy=self.local_healthy,
            local_error=str(local_error) if local_error else None,
            cloud_error=str(cloud_error) if cloud_error else None,
        )
