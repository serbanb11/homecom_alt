"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .model import (
    BHCDeviceGeneric,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


class HomeComGeneric(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type generic."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize RAC device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "generic"

    async def async_update(self, device_id: str) -> BHCDeviceGeneric:
        """Retrieve data from the device."""
        await self.get_token()

        return BHCDeviceGeneric(
            device=device_id,
            firmware=[],
            notifications=[],
        )
