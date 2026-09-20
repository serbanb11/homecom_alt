"""Bhc exceptions."""


class BhcError(Exception):
    """Base class for BHC errors."""

    def __init__(self, status: str) -> None:
        """Initialize."""
        super().__init__(status)
        self.status = status


class ApiError(BhcError):
    """Raised when request ended in error."""


class NotRespondingError(BhcError):
    """Raised when device is not responding."""


class AuthFailedError(BhcError):
    """Raised if auth fails."""


class InvalidSensorDataError(BhcError):
    """Raised when sensor data is invalid."""


class MqttNotAuthorizedError(ApiError):
    """Raised when the MQTT broker refuses the presented credentials.

    The bacon broker takes the access token as the MQTT password, so an expired
    token makes an otherwise healthy session unusable. That is a *transport*
    credential failure, deliberately **not** an :class:`AuthFailedError`: the
    OAuth refresh token is still fine and the caller only has to reconnect with
    a freshly rotated access token. Keeping it outside the ``AuthFailedError``
    hierarchy stops existing ``except AuthFailedError`` handlers from turning it
    into a spurious re-authentication request.
    """


class ProximityRequiredError(BhcError):
    """Raised when the K 40 RF Local API refuses a token for lack of proximity proof.

    The gateway answers ``412 physical_proximity_unproven`` until the WLAN and
    Wireless buttons have been pressed together, which opens a five-minute
    window for the token request. This is deliberately **not** an
    :class:`AuthFailedError`: the credentials may be perfectly correct and the
    caller only has to prompt the user for a physical button press and retry, so
    existing ``except AuthFailedError`` handlers must not turn it into a
    re-authentication request.
    """


class TokenStoreFullError(BhcError):
    """Raised when the gateway's token store cannot accept another token.

    The gateway answers ``507`` once its token database is full. Recovery is to
    revoke an unused token rather than to retry, so this is separated from the
    generic :class:`ApiError`.
    """
