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
