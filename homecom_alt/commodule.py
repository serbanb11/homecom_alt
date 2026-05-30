"""Python wrapper for controlling homecom easy devices."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from .base import HomeComAlt
from .const import (
    BOSCHCOM_DOMAIN,
    BOSCHCOM_ENDPOINT_CP,
    BOSCHCOM_ENDPOINT_CP_CHARGELOG,
    BOSCHCOM_ENDPOINT_CP_CMD_AUTHENTICATE,
    BOSCHCOM_ENDPOINT_CP_CMD_LIMIT,
    BOSCHCOM_ENDPOINT_CP_CMD_PAUSE,
    BOSCHCOM_ENDPOINT_CP_CMD_START,
    BOSCHCOM_ENDPOINT_CP_CONF,
    BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
    BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
    BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
    BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
    BOSCHCOM_ENDPOINT_CP_INFO,
    BOSCHCOM_ENDPOINT_CP_TELEMETRY,
    BOSCHCOM_ENDPOINT_ETH0_STATE,
    BOSCHCOM_ENDPOINT_GATEWAYS,
    BOSCHCOM_ENDPOINT_WIFI_STATE,
)
from .model import (
    BHCDeviceCommodule,
)

if TYPE_CHECKING:
    from aiohttp import (
        ClientSession,
    )

_LOGGER = logging.getLogger(__name__)

_NOT_FOUND_CACHE_TTL: float = 86400.0  # 24 hours


class HomeComCommodule(HomeComAlt):
    """Main class to perform HomeCom Easy requests for device type commodule."""

    def __init__(
        self, session: ClientSession, options: Any, device_id: str, auth_provider: bool
    ) -> None:
        """Initialize commodule device."""
        super().__init__(session, options, auth_provider)
        self.device_id = device_id
        self.device_type = "commodule"

    async def async_get_charge_points(self, device_id: str) -> Any:
        """Get charge points."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP,
        )
        return await self._to_data(response)

    async def async_get_cp_conf(self, device_id: str, cp_id: str) -> Any:
        """Get charge point configuration."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF,
        )
        return await self._to_data(response)

    async def async_get_cp_info(self, device_id: str, cp_id: str) -> Any:
        """Get charge point info."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_INFO,
        )
        return await self._to_data(response)

    async def async_get_cp_telemetry(self, device_id: str, cp_id: str) -> Any:
        """Get charge point telemetry."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_TELEMETRY,
        )
        return await self._to_data(response)

    async def async_get_cp_chargelog(self, device_id: str, cp_id: str) -> Any:
        """Get charge point charge log."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CHARGELOG,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_price(self, device_id: str, cp_id: str) -> Any:
        """Get charge point electricity price."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_locked(self, device_id: str, cp_id: str) -> Any:
        """Get charge point lock state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_auth(self, device_id: str, cp_id: str) -> Any:
        """Get charge point auth setting."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
        )
        return await self._to_data(response)

    async def async_get_cp_conf_rfid_secure(self, device_id: str, cp_id: str) -> Any:
        """Get charge point RFID security setting."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
        )
        return await self._to_data(response)

    async def async_get_eth0_state(self, device_id: str) -> Any:
        """Get ethernet connection state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_ETH0_STATE,
        )
        return await self._to_data(response)

    async def async_get_wifi_state(self, device_id: str) -> Any:
        """Get wifi connection state."""
        await self.get_token()
        response = await self._async_http_request(
            "get",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_WIFI_STATE,
        )
        return await self._to_data(response)

    async def async_put_cp_conf_price(
        self, device_id: str, cp_id: str, price: float
    ) -> None:
        """Set charge point electricity price."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_PRICE,
            {"value": round(price, 2)},
            1,
        )

    async def async_put_cp_conf_locked(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point lock state."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_LOCKED,
            {"value": value},
            1,
        )

    async def async_put_cp_conf_auth(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point auth setting."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_AUTH,
            {"value": value},
            1,
        )

    async def async_put_cp_conf_rfid_secure(
        self, device_id: str, cp_id: str, value: str
    ) -> None:
        """Set charge point RFID security setting."""
        await self.get_token()
        await self._async_http_request(
            "put",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CONF_RFID_SECURE,
            {"value": value},
            1,
        )

    async def async_cp_authenticate(
        self, device_id: str, cp_id: str, name: str
    ) -> None:
        """Authenticate on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_AUTHENTICATE,
            {"name": name},
            1,
        )

    async def async_cp_start_charging(
        self, device_id: str, cp_id: str, label: str
    ) -> None:
        """Start charging on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_START,
            {"name": label},
            1,
        )

    async def async_cp_pause_charging(
        self, device_id: str, cp_id: str, label: str
    ) -> None:
        """Pause charging on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_PAUSE,
            {"name": label},
            1,
        )

    async def async_cp_set_limit(self, device_id: str, cp_id: str, limit: int) -> None:
        """Set charging limit on charge point."""
        await self.get_token()
        await self._async_http_request(
            "post",
            BOSCHCOM_DOMAIN
            + BOSCHCOM_ENDPOINT_GATEWAYS
            + device_id
            + BOSCHCOM_ENDPOINT_CP
            + "/"
            + cp_id
            + BOSCHCOM_ENDPOINT_CP_CMD_LIMIT,
            {"limit": limit},
            1,
        )

    async def async_update(self, device_id: str) -> BHCDeviceCommodule:
        """Retrieve data from the device."""
        await self.get_token()

        notifications = await self.async_get_notifications(device_id)
        eth0_state = await self.async_get_eth0_state(device_id)
        wifi_state = await self.async_get_wifi_state(device_id)
        charge_points_data = await self.async_get_charge_points(device_id)
        charge_points_data = charge_points_data or {}
        references = charge_points_data.get("references", [])
        if references:
            for ref in references:
                cp_id = ref["id"].split("/")[-1]
                if re.fullmatch(r"cp\d+", cp_id):
                    ref["conf"] = await self.async_get_cp_conf(device_id, cp_id)
                    ref["info"] = await self.async_get_cp_info(device_id, cp_id)
                    ref["telemetry"] = await self.async_get_cp_telemetry(
                        device_id, cp_id
                    )
                    ref["chargelog"] = await self.async_get_cp_chargelog(
                        device_id, cp_id
                    )
                    ref["price"] = await self.async_get_cp_conf_price(device_id, cp_id)
                    ref["locked"] = await self.async_get_cp_conf_locked(
                        device_id, cp_id
                    )
                    ref["auth"] = await self.async_get_cp_conf_auth(device_id, cp_id)
                    ref["rfidSecure"] = await self.async_get_cp_conf_rfid_secure(
                        device_id, cp_id
                    )
        else:
            charge_points_data["references"] = {}

        return BHCDeviceCommodule(
            device=device_id,
            firmware=[],
            notifications=((notifications or {}).get("values") or []),
            charge_points=charge_points_data.get("references", {}),
            eth0_state=eth0_state,
            wifi_state=wifi_state,
        )
