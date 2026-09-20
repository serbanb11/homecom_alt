"""Tests for the K 40 RF Local API client and the local-first update policy."""

# pylint: disable=protected-access

import asyncio
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import (
    ClientConnectorError,
    ClientError,
    ClientResponseError,
    ClientSession,
)

from homecom_alt import (
    ApiError,
    AuthFailedError,
    BHCDeviceK40Local,
    HomeComK40Local,
    HomeComK40LocalFirst,
    NotRespondingError,
    ProximityRequiredError,
    TokenStoreFullError,
)
from homecom_alt.const import (
    DEFAULT_TIMEOUT,
    LOCAL_API_PORT,
    LOCAL_AUTH_PORT,
    LOCAL_MAX_CONCURRENT,
    LOCAL_TIMEOUT,
)

HOST = "192.0.2.10"
TOKEN = "local-access-token"  # test fixture, not a real secret

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resp(data, status=HTTPStatus.OK):  # noqa: ANN001, ANN202
    """Return an AsyncMock that behaves like an aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=data)
    return resp


def _http_error(status):  # noqa: ANN001, ANN202
    """Return a ClientResponseError with the given status."""
    return ClientResponseError(MagicMock(), (), status=status)


def _float_value(path, value, unit="C"):  # noqa: ANN001, ANN202
    """Build a floatValue resource payload as the gateway returns it."""
    return {
        "id": path,
        "type": "floatValue",
        "writeable": 0,
        "value": value,
        "unitOfMeasure": unit,
    }


def _string_value(path, value):  # noqa: ANN001, ANN202
    """Build a stringValue resource payload as the gateway returns it."""
    return {"id": path, "type": "stringValue", "writeable": 0, "value": value}


# ---------------------------------------------------------------------------
# Token management (port 9442)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_token_success_sets_token() -> None:
    """A successful token request returns the payload and applies the token."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    payload = {
        "access_token": "new-token",
        "token_type": "Bearer",
        "scope": "open_api.read",
    }
    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(payload)
        result = await client.async_create_token("login", "pass", "client")

        assert result == payload
        assert client.token == "new-token"
        # Token requests go to the auth port, never the resource port.
        assert f":{LOCAL_AUTH_PORT}/auth/token" in request.call_args.args[1]

    await session.close()


@pytest.mark.asyncio
async def test_create_token_strips_hyphens_from_password() -> None:
    """The gateway expects the label Pass without hyphens."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp({"access_token": "t"})
        await client.async_create_token("login", "abcd-efgh-ijkl", "client")

        assert request.call_args.kwargs["data"]["password"] == "abcdefghijkl"

    await session.close()


@pytest.mark.asyncio
async def test_create_token_proximity_required() -> None:
    """412 becomes ProximityRequiredError, not an auth failure."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(412)
        with pytest.raises(ProximityRequiredError):
            await client.async_create_token("login", "pass", "client")

    await session.close()


def test_proximity_error_is_not_an_auth_error() -> None:
    """A 412 must not be caught by ``except AuthFailedError`` handlers."""
    assert not issubclass(ProximityRequiredError, AuthFailedError)
    assert not issubclass(TokenStoreFullError, AuthFailedError)


@pytest.mark.asyncio
async def test_create_token_store_full() -> None:
    """507 becomes TokenStoreFullError so the caller knows to revoke one."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(507)
        with pytest.raises(TokenStoreFullError):
            await client.async_create_token("login", "pass", "client")

    await session.close()


@pytest.mark.asyncio
async def test_create_token_bad_credentials() -> None:
    """A 400 invalid_grant surfaces as ApiError."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(HTTPStatus.BAD_REQUEST)
        with pytest.raises(ApiError):
            await client.async_create_token("login", "pass", "client")

    await session.close()


@pytest.mark.asyncio
async def test_create_token_without_access_token_raises() -> None:
    """A 200 that carries no access_token is still a failure."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp({"token_type": "Bearer"})
        with pytest.raises(ApiError):
            await client.async_create_token("login", "pass", "client")
        assert client.token is None

    await session.close()


@pytest.mark.asyncio
async def test_list_tokens_accepts_iso_created_at() -> None:
    """created_at is an ISO string on firmware 15.00.01, not an epoch int."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    tokens = [
        {
            "token_type": "Bearer",
            "token_id": "1",
            "client_name": "ha",
            "created_at": "2026-09-20T11:43:52Z",
        }
    ]
    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(tokens)
        assert await client.async_list_tokens() == tokens

    await session.close()


@pytest.mark.asyncio
async def test_list_tokens_unexpected_shape_raises() -> None:
    """A non-list token listing is an error rather than silently empty."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp({"unexpected": True})
        with pytest.raises(ApiError):
            await client.async_list_tokens()

    await session.close()


@pytest.mark.asyncio
async def test_revoke_token_posts_form_fields() -> None:
    """Revocation posts token_id and usage_type to the auth port."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(None, status=HTTPStatus.NO_CONTENT)
        await client.async_revoke_token("1")

        assert request.call_args.kwargs["data"] == {
            "token_id": "1",
            "usage_type": "private",
        }
        assert f":{LOCAL_AUTH_PORT}/auth/revoke" in request.call_args.args[1]

    await session.close()


# ---------------------------------------------------------------------------
# Resource reads (port 9443)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_resource_returns_payload_from_api_port() -> None:
    """A resource read hits the resource port and returns the payload."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)
    path = "/dhwCircuits/dhw1/actualTemp"

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(_float_value(path, 55.6))
        result = await client.async_get_resource(path)

        assert result is not None
        assert result["value"] == 55.6
        assert f":{LOCAL_API_PORT}{path}" in request.call_args.args[1]

    await session.close()


@pytest.mark.asyncio
async def test_tls_verification_is_disabled() -> None:
    """The gateway certificate CN is the device id, so ssl must be disabled.

    Pinned deliberately: flipping this to True would break every install.
    """
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(_string_value("/gateway/brand", "Bosch"))
        await client.async_get_resource("/gateway/brand")

        assert request.call_args.kwargs["ssl"] is False

    await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [HTTPStatus.NOT_FOUND, HTTPStatus.FORBIDDEN])
async def test_absent_resource_is_cached_and_not_reprobed(status) -> None:  # noqa: ANN001
    """A local 404/403 is structural, so it is remembered permanently."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)
    path = "/pool/currentTemp"

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(status)

        assert await client.async_get_resource(path) is None
        assert request.call_count == 1
        assert path in client.unsupported

        # Second read must not produce another request.
        assert await client.async_get_resource(path) is None
        assert request.call_count == 1

    await session.close()


@pytest.mark.asyncio
async def test_rejected_token_raises_auth_failed() -> None:
    """A 401 on a resource read is an auth failure."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(HTTPStatus.UNAUTHORIZED)
        with pytest.raises(AuthFailedError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_missing_token_fails_before_any_request() -> None:
    """Reading without a token fails locally instead of hitting the gateway."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        with pytest.raises(AuthFailedError):
            await client.async_get_resource("/gateway/brand")
        request.assert_not_called()

    await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError(),
        ClientConnectorError(MagicMock(), OSError("unreachable")),
    ],
)
async def test_transport_failure_is_not_responding(exc) -> None:  # noqa: ANN001
    """Timeouts and connection failures map to NotRespondingError."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = exc
        with pytest.raises(NotRespondingError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [HTTPStatus.BAD_GATEWAY, HTTPStatus.GATEWAY_TIMEOUT])
async def test_gateway_5xx_is_not_responding(status) -> None:  # noqa: ANN001
    """502/504 are transient, so they are retryable rather than fatal."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(status)
        with pytest.raises(NotRespondingError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_unexpected_status_is_api_error() -> None:
    """An undocumented status is a hard error."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        with pytest.raises(ApiError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_non_dict_resource_payload_raises() -> None:
    """A resource that is not an object is a protocol violation."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(["unexpected"])
        with pytest.raises(ApiError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_get_resources_omits_absent_and_keeps_present() -> None:
    """Absent resources drop out rather than appearing as None."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    async def route(_method, url, **_kwargs):  # noqa: ANN001, ANN003, ANN202
        if "pool" in url:
            raise _http_error(HTTPStatus.NOT_FOUND)
        return _resp(_float_value("/x", 1.0))

    with patch.object(ClientSession, "request", new=AsyncMock(side_effect=route)):
        result = await client.async_get_resources(
            ["/heatSources/systemPressure", "/pool/currentTemp"]
        )

    assert "/heatSources/systemPressure" in result
    assert "/pool/currentTemp" not in result

    await session.close()


@pytest.mark.asyncio
async def test_get_resources_respects_concurrency_cap() -> None:
    """The gateway serialises internally, so never exceed the cap in flight."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    in_flight = 0
    peak = 0

    async def route(_method, _url, **_kwargs):  # noqa: ANN001, ANN003, ANN202
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.01)
        in_flight -= 1
        return _resp(_float_value("/x", 1.0))

    with patch.object(ClientSession, "request", new=AsyncMock(side_effect=route)):
        await client.async_get_resources([f"/r{i}" for i in range(12)])

    assert peak <= LOCAL_MAX_CONCURRENT

    await session.close()


# ---------------------------------------------------------------------------
# Recordings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recording_rejects_non_iso_sample_rate() -> None:
    """A non-ISO rate like 1h is rejected locally, before reaching the gateway."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        with pytest.raises(ApiError):
            await client.async_get_recording("/recordings/x", "1h")
        request.assert_not_called()

    await session.close()


@pytest.mark.asyncio
async def test_recording_builds_query_with_dates() -> None:
    """Sample rate and optional dates are passed through as query parameters."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp({"id": "/recordings/x", "values": []})
        await client.async_get_recording(
            "/recordings/x", "P1D", start_date="2026-05-30", end_date="2026-09-20"
        )

        url = request.call_args.args[1]
        assert "sampleRate=P1D" in url
        assert "startDate=2026-05-30" in url
        assert "endDate=2026-09-20" in url

    await session.close()


# ---------------------------------------------------------------------------
# async_update and derived DHW mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_returns_device_with_derived_mode() -> None:
    """A full update collects resources and derives the DHW mode."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN, device_id="102128202")

    async def route(_method, url, **_kwargs):  # noqa: ANN001, ANN003, ANN202
        if url.endswith("/dhwCircuits/dhw1/overallStatus"):
            return _resp(_string_value("x", "manual_on_eco"))
        if url.endswith("/heatingCircuits/hc1/overallStatus"):
            return _resp(_string_value("x", "heating_manual_off"))
        if url.endswith("/gateway/versionFirmware"):
            return _resp(_string_value("x", "15.00.01"))
        return _resp(_float_value("x", 1.0))

    with patch.object(ClientSession, "request", new=AsyncMock(side_effect=route)):
        device = await client.async_update()

    assert isinstance(device, BHCDeviceK40Local)
    assert device.device == "102128202"
    assert device.firmware == "15.00.01"
    assert device.dhw_mode == "eco"
    assert device.hc_status == "heating_manual_off"
    assert device.resources["/dhwCircuits/dhw1/overallStatus"]["value"] == (
        "manual_on_eco"
    )

    await session.close()


@pytest.mark.asyncio
async def test_update_with_no_resources_raises() -> None:
    """A gateway that answers nothing is an error, not an empty device."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(HTTPStatus.NOT_FOUND)
        with pytest.raises(ApiError):
            await client.async_update()

    await session.close()


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("manual_off", "Off"),
        ("manual_on_eco", "eco"),
        ("manual_on_low", "low"),
        ("manual_on_high", "high"),
        ("auto", "ownprogram"),
        # No mode equivalent: must be None, never silently "Off".
        ("away", None),
        ("holiday", None),
        ("extra", None),
        ("td", None),
        ("floor_drying", None),
        ("dhw_disabled", None),
    ],
)
def test_dhw_mode_mapping(status, expected) -> None:  # noqa: ANN001
    """Each overallStatus value maps onto the cloud operationMode vocabulary."""
    resources = {"/dhwCircuits/dhw1/overallStatus": _string_value("x", status)}
    assert HomeComK40Local.dhw_mode(resources) == expected


def test_dhw_mode_without_resource_is_none() -> None:
    """A missing status resource yields no mode."""
    assert HomeComK40Local.dhw_mode({}) is None


# ---------------------------------------------------------------------------
# Local-first policy
# ---------------------------------------------------------------------------


def _local_first(local_side, cloud_side, **kwargs):  # noqa: ANN001, ANN003, ANN202
    """Build a HomeComK40LocalFirst over two mocked clients."""
    local = MagicMock()
    local.async_update = AsyncMock(side_effect=local_side)
    cloud = MagicMock()
    cloud.async_update = AsyncMock(side_effect=cloud_side)
    return HomeComK40LocalFirst(local, cloud, **kwargs), local, cloud


LOCAL_DEVICE = BHCDeviceK40Local(device="d", firmware="15.00.01", resources={"/a": {}})
CLOUD_DEVICE = MagicMock(name="BHCDeviceK40")


@pytest.mark.asyncio
async def test_both_transports_succeed() -> None:
    """When both work, both payloads are returned."""
    policy, _, _ = _local_first([LOCAL_DEVICE], [CLOUD_DEVICE])
    update = await policy.async_update("dev")

    assert update.source == "both"
    assert update.local is LOCAL_DEVICE
    assert update.cloud is CLOUD_DEVICE
    assert update.local_healthy is True


@pytest.mark.asyncio
async def test_cloud_outage_still_serves_local() -> None:
    """A cloud 504 must not make the device unavailable."""
    policy, _, _ = _local_first([LOCAL_DEVICE], [NotRespondingError("bulk")])
    update = await policy.async_update("dev")

    assert update.source == "local"
    assert update.local is LOCAL_DEVICE
    assert update.cloud is None
    assert update.cloud_error is not None


@pytest.mark.asyncio
async def test_local_failure_falls_back_to_cloud() -> None:
    """A local miss falls back to the cloud and is counted."""
    policy, _, _ = _local_first([NotRespondingError("gw")], [CLOUD_DEVICE])
    update = await policy.async_update("dev")

    assert update.source == "cloud"
    assert update.local is None
    assert policy.local_failures == 1
    assert update.local_healthy is True  # one miss is not unhealthy


@pytest.mark.asyncio
async def test_local_unhealthy_after_threshold() -> None:
    """Repeated local failures mark the local transport unhealthy."""
    policy, _, _ = _local_first(
        [NotRespondingError("gw")] * 3, [CLOUD_DEVICE] * 3, failure_threshold=3
    )
    for _ in range(3):
        update = await policy.async_update("dev")

    assert policy.local_failures == 3
    assert policy.local_healthy is False
    assert update.local_healthy is False


@pytest.mark.asyncio
async def test_local_recovery_resets_failure_count() -> None:
    """A successful local read clears the failure counter."""
    policy, _, _ = _local_first(
        [NotRespondingError("gw"), LOCAL_DEVICE], [CLOUD_DEVICE, CLOUD_DEVICE]
    )
    await policy.async_update("dev")
    assert policy.local_failures == 1

    update = await policy.async_update("dev")
    assert policy.local_failures == 0
    assert update.source == "both"


@pytest.mark.asyncio
async def test_rejected_local_token_parks_local_reads() -> None:
    """A rejected local token stops being retried every poll."""
    policy, local, _ = _local_first(
        [AuthFailedError("401"), LOCAL_DEVICE],
        [CLOUD_DEVICE, CLOUD_DEVICE, CLOUD_DEVICE],
    )

    first = await policy.async_update("dev")
    assert first.source == "cloud"
    assert policy.local_disabled is True
    assert policy.local_healthy is False

    second = await policy.async_update("dev")
    assert second.source == "cloud"
    # The local client must not have been called a second time.
    assert local.async_update.await_count == 1

    policy.reset_local()
    assert policy.local_disabled is False
    third = await policy.async_update("dev")
    assert third.source == "both"
    assert local.async_update.await_count == 2


@pytest.mark.asyncio
async def test_cloud_auth_failure_is_reraised() -> None:
    """Cloud auth failures must reach the caller so reauth can be triggered."""
    policy, _, _ = _local_first([LOCAL_DEVICE], [AuthFailedError("401")])

    with pytest.raises(AuthFailedError):
        await policy.async_update("dev")


@pytest.mark.asyncio
async def test_both_failing_raises_cloud_error() -> None:
    """When nothing works the cloud error is raised, being the actionable one."""
    policy, _, _ = _local_first(
        [NotRespondingError("gw")], [NotRespondingError("cloud")]
    )

    with pytest.raises(NotRespondingError):
        await policy.async_update("dev")


# ---------------------------------------------------------------------------
# Accessors and remaining error branches
# ---------------------------------------------------------------------------


def test_host_and_token_accessors() -> None:
    """Host is exposed read-only; the token can be replaced after provisioning."""
    session = MagicMock()
    client = HomeComK40Local(session, HOST)

    assert client.host == HOST
    assert client.token is None
    assert client.unsupported == ()

    client.token = "replacement"
    assert client.token == "replacement"


@pytest.mark.asyncio
async def test_generic_client_error_is_api_error() -> None:
    """An aiohttp ClientError that is not a timeout is a hard error."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = ClientError("boom")
        with pytest.raises(ApiError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_invalid_json_body_is_api_error() -> None:
    """A 200 whose body is not JSON is a protocol violation."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    resp = AsyncMock()
    resp.status = HTTPStatus.OK
    resp.json = AsyncMock(side_effect=ValueError("not json"))

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = resp
        with pytest.raises(ApiError):
            await client.async_get_resource("/gateway/brand")

    await session.close()


@pytest.mark.asyncio
async def test_no_content_response_is_none() -> None:
    """A 204 carries no body and must not be parsed as JSON."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    resp = AsyncMock()
    resp.status = HTTPStatus.NO_CONTENT
    resp.json = AsyncMock(side_effect=AssertionError("must not parse a 204 body"))

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = resp
        # Treated as an absent resource, and remembered as such.
        assert await client.async_get_resource("/gateway/brand") is None

    await session.close()


@pytest.mark.asyncio
async def test_recording_non_dict_payload_raises() -> None:
    """A recording that is not an object is a protocol violation."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp([1, 2, 3])
        with pytest.raises(ApiError):
            await client.async_get_recording("/recordings/x", "P1D")

    await session.close()


@pytest.mark.asyncio
async def test_recording_absent_returns_none() -> None:
    """A 404 on a recording means this system does not record that resource."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.side_effect = _http_error(HTTPStatus.NOT_FOUND)
        assert await client.async_get_recording("/recordings/x", "PT1H") is None

    await session.close()


# ---------------------------------------------------------------------------
# Failing fast when the gateway goes away
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_read_fails_fast_on_transport_error() -> None:
    """One transport error aborts the remaining reads.

    Without this, an unreachable gateway costs
    (resources / concurrency) x timeout before failing, which for the default
    poll set is minutes -- long enough to stall a consumer's update cycle.
    """
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    attempts = 0

    async def route(_method, _url, **_kwargs):  # noqa: ANN001, ANN003, ANN202
        nonlocal attempts
        attempts += 1
        raise TimeoutError

    with (
        patch.object(ClientSession, "request", new=AsyncMock(side_effect=route)),
        pytest.raises(NotRespondingError),
    ):
        await client.async_get_resources([f"/r{i}" for i in range(40)])

    # Only the reads already past the semaphore are attempted, not all 40.
    assert attempts <= LOCAL_MAX_CONCURRENT

    await session.close()


@pytest.mark.asyncio
async def test_update_is_bounded_by_a_time_budget() -> None:
    """A gateway that accepts connections but never answers cannot hang a poll."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    async def never_answers(_method, _url, **_kwargs):  # noqa: ANN001, ANN003, ANN202
        await asyncio.sleep(3600)

    with (
        patch.object(
            ClientSession, "request", new=AsyncMock(side_effect=never_answers)
        ),
        patch("homecom_alt.local.LOCAL_UPDATE_BUDGET", 0.05),
        pytest.raises(NotRespondingError),
    ):
        await client.async_update()

    await session.close()


@pytest.mark.asyncio
async def test_local_timeout_is_shorter_than_the_cloud_default() -> None:
    """A LAN gateway answers in ~50 ms, so it must not wait 15 s to give up."""
    session = ClientSession()
    client = HomeComK40Local(session, HOST, TOKEN)

    with patch.object(ClientSession, "request", new=AsyncMock()) as request:
        request.return_value = _resp(_string_value("/gateway/brand", "Bosch"))
        await client.async_get_resource("/gateway/brand")

        assert request.call_args.kwargs["timeout"] is LOCAL_TIMEOUT
        assert LOCAL_TIMEOUT.total < DEFAULT_TIMEOUT.total

    await session.close()
