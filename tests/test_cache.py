"""
Tests for iam/cache.py (empty stub) and iam/client.py IAMClient cache behavior.
Also covers core/config.py and core/context.py.
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# iam/cache.py — empty module, import check
# ---------------------------------------------------------------------------

def test_iam_cache_module_importable():
    import iam.cache as cache_mod
    assert cache_mod is not None


# ---------------------------------------------------------------------------
# iam/client.py — IAMClient  (cache + remote validation)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_validate_cache_hit_returns_parsed_data(iam_client_setup):
    client, mock_redis, _ = iam_client_setup
    user_data = {"user_id": "u1", "email": "u1@test.com", "valid": True}
    mock_redis.get = AsyncMock(return_value=json.dumps(user_data))

    result = await client.validate("test-token")

    assert result == user_data
    mock_redis.get.assert_called_once_with("iam:test-token")


@pytest.mark.asyncio
async def test_validate_cache_miss_hits_remote(iam_client_setup):
    client, mock_redis, mock_http = iam_client_setup
    mock_redis.get = AsyncMock(return_value=None)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"valid": True, "user_id": "u2", "email": "u2@t.com"}
    mock_http.post = AsyncMock(return_value=mock_response)
    mock_redis.setex = AsyncMock()

    result = await client.validate("new-token")

    assert result["user_id"] == "u2"
    mock_http.post.assert_called_once()


@pytest.mark.asyncio
async def test_validate_remote_caches_result(iam_client_setup):
    client, mock_redis, mock_http = iam_client_setup
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    user_data = {"valid": True, "user_id": "u3", "email": "u3@t.com"}
    mock_response = MagicMock(status_code=200, json=lambda: user_data)
    mock_http.post = AsyncMock(return_value=mock_response)

    await client.validate("cache-this-token")

    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args[0]
    assert call_args[0] == "iam:cache-this-token"
    assert call_args[1] == 300
    assert json.loads(call_args[2]) == user_data


@pytest.mark.asyncio
async def test_validate_non_200_returns_none(iam_client_setup):
    client, mock_redis, mock_http = iam_client_setup
    mock_redis.get = AsyncMock(return_value=None)
    mock_response = MagicMock(status_code=401)
    mock_http.post = AsyncMock(return_value=mock_response)

    result = await client.validate("bad-token")

    assert result is None


@pytest.mark.asyncio
async def test_validate_invalid_response_returns_none(iam_client_setup):
    client, mock_redis, mock_http = iam_client_setup
    mock_redis.get = AsyncMock(return_value=None)
    mock_response = MagicMock(status_code=200, json=lambda: {"valid": False})
    mock_http.post = AsyncMock(return_value=mock_response)

    result = await client.validate("invalid-token")

    assert result is None


@pytest.mark.asyncio
async def test_validate_does_not_cache_invalid(iam_client_setup):
    client, mock_redis, mock_http = iam_client_setup
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    mock_response = MagicMock(status_code=200, json=lambda: {"valid": False})
    mock_http.post = AsyncMock(return_value=mock_response)

    await client.validate("invalid-token")

    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# audit/client.py — AuditClient
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_client_emit_calls_xadd():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("audit.client.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        from audit.client import AuditClient
        ac = AuditClient(redis_url="redis://localhost")
        ac.redis = mock_redis

    await ac.emit({"event_type": "auth_login", "user_id": "u1"})

    mock_redis.xadd.assert_called_once()


@pytest.mark.asyncio
async def test_audit_client_emits_to_correct_stream():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("audit.client.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        from audit.client import AuditClient
        ac = AuditClient(redis_url="redis://localhost")
        ac.redis = mock_redis

    await ac.emit({"event_type": "test"})

    stream_name = mock_redis.xadd.call_args[0][0]
    assert stream_name == "audit:events"


@pytest.mark.asyncio
async def test_audit_client_serializes_event():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock()

    with patch("audit.client.redis") as mock_redis_module:
        mock_redis_module.from_url.return_value = mock_redis
        from audit.client import AuditClient
        ac = AuditClient(redis_url="redis://localhost")
        ac.redis = mock_redis

    event = {"event_type": "login", "user_id": "u99"}
    await ac.emit(event)

    raw = mock_redis.xadd.call_args[0][1]["data"]
    assert json.loads(raw) == event


# ---------------------------------------------------------------------------
# core/config.py
# ---------------------------------------------------------------------------

def test_security_config_has_iam_url():
    from core.config import SecurityConfig
    assert SecurityConfig.IAM_BASE_URL is not None


def test_security_config_has_policy_url():
    from core.config import SecurityConfig
    assert SecurityConfig.POLICY_BASE_URL is not None


def test_security_config_has_redis_url():
    from core.config import SecurityConfig
    assert SecurityConfig.REDIS_URL is not None


def test_security_config_has_service_name():
    from core.config import SecurityConfig
    assert SecurityConfig.SERVICE_NAME is not None


def test_security_config_has_service_secret():
    from core.config import SecurityConfig
    assert SecurityConfig.SERVICE_SECRET is not None


# ---------------------------------------------------------------------------
# core/context.py
# ---------------------------------------------------------------------------

def test_set_and_get_user():
    from core.context import set_user, get_user, user_ctx
    token = user_ctx.set(None)
    try:
        set_user({"user_id": "u1"})
        assert get_user() == {"user_id": "u1"}
    finally:
        user_ctx.reset(token)


def test_user_context_default_is_none():
    from core.context import get_user, user_ctx
    token = user_ctx.set(None)
    try:
        assert get_user() is None
    finally:
        user_ctx.reset(token)


def test_set_and_get_service():
    from core.context import set_service, get_service, service_ctx
    token = service_ctx.set(None)
    try:
        set_service("my-service")
        assert get_service() == "my-service"
    finally:
        service_ctx.reset(token)


def test_service_context_default_is_none():
    from core.context import get_service, service_ctx
    token = service_ctx.set(None)
    try:
        assert get_service() is None
    finally:
        service_ctx.reset(token)


def test_set_and_get_trace():
    from core.context import set_trace, get_trace, trace_ctx
    token = trace_ctx.set(None)
    try:
        set_trace("trace-xyz")
        assert get_trace() == "trace-xyz"
    finally:
        trace_ctx.reset(token)


def test_trace_context_default_is_none():
    from core.context import get_trace, trace_ctx
    token = trace_ctx.set(None)
    try:
        assert get_trace() is None
    finally:
        trace_ctx.reset(token)
