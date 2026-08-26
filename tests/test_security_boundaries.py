"""tests/test_security_boundaries.py — targeted security-boundary coverage.

Complements the existing suite (test_middleware.py, test_cache.py, etc.), which
already drives every production module to 100% line/branch coverage. This file
adds *behavioral* assertions for scenarios coverage percentage alone doesn't
guarantee were ever exercised: token expiry/timing claims, algorithm-confusion
resistance, fail-open vs. fail-closed behavior on malformed upstream data,
claim type-confusion, and unhandled-exception propagation at trust boundaries.

Some tests here document pre-existing production behavior (including two
findings that are arguably bugs) without asserting it is *correct* -- see the
inline notes on `test_s2s_aud_as_substring_bypasses_check` and
`test_iam_validate_truthy_string_valid_field_treated_as_valid`. Per the
test-only mandate for this audit, production code is not modified; these
tests exist to pin current behavior and make the gap visible to reviewers.
"""
from __future__ import annotations

import importlib
import json
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse


# ---------------------------------------------------------------------------
# Bridge: make `omnibioai_security_sdk.*` resolve to local root modules
# (same pattern as tests/test_middleware.py)
# ---------------------------------------------------------------------------
def _ensure_sdk_namespace():
    if "omnibioai_security_sdk" in sys.modules:
        return
    root_ns = types.ModuleType("omnibioai_security_sdk")
    sub_names = ["iam", "iam.client", "iam.cache",
                 "core", "core.context", "core.config",
                 "policy", "policy.client", "policy.decorator",
                 "auth", "auth.service", "auth.user",
                 "audit", "audit.client",
                 "exceptions",
                 "middleware", "middleware.auth", "middleware.policy", "middleware.s2s"]
    for name in sub_names:
        parts = name.split(".")
        try:
            real = importlib.import_module(".".join(parts))
        except Exception:
            real = types.ModuleType(f"omnibioai_security_sdk.{name}")
        sys.modules[f"omnibioai_security_sdk.{name}"] = real
        parent = root_ns
        for part in parts[:-1]:
            parent = sys.modules.get(f"omnibioai_security_sdk.{part}", parent)
        setattr(parent, parts[-1], real)
    sys.modules["omnibioai_security_sdk"] = root_ns


_ensure_sdk_namespace()


def _make_scope(method="GET", path="/", headers=None):
    raw = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    return {"type": "http", "method": method, "path": path, "headers": raw, "query_string": b""}


def _body(response):
    return json.loads(response.body)


async def _call_next(request):
    return JSONResponse({"ok": True})


# ===========================================================================
# middleware/s2s.py — ServiceAuthMiddleware: JWT boundary conditions
# ===========================================================================

class TestServiceAuthMiddlewareTokenBoundaries:

    def _middleware(self, secret="secret", service_name="svc-a"):
        from starlette.applications import Starlette
        from starlette.routing import Route

        from middleware.s2s import ServiceAuthMiddleware

        async def endpoint(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", endpoint)])
        return ServiceAuthMiddleware(app, secret=secret, service_name=service_name)

    def _jwt(self, payload, secret="secret"):
        return jwt.encode(payload, secret, algorithm="HS256")

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self):
        import time
        tok = self._jwt({"service": "caller", "aud": ["svc-a"], "exp": int(time.time()) - 100})
        mw = self._middleware()
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "invalid service token"

    @pytest.mark.asyncio
    async def test_not_yet_valid_nbf_token_returns_401(self):
        import time
        tok = self._jwt({"service": "caller", "aud": ["svc-a"], "nbf": int(time.time()) + 1000})
        mw = self._middleware()
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "invalid service token"

    @pytest.mark.asyncio
    async def test_none_algorithm_attack_is_rejected(self):
        """PyJWT must refuse an unsigned 'alg: none' token even though the
        payload otherwise satisfies the audience check -- the middleware
        hardcodes algorithms=["HS256"], so this must 401, not bypass auth."""
        forged = jwt.encode({"service": "attacker", "aud": ["svc-a"]}, key="", algorithm="none")
        mw = self._middleware()
        request = Request(_make_scope(headers={"x-service-token": forged}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "invalid service token"

    @pytest.mark.asyncio
    async def test_empty_audience_list_denied(self):
        tok = self._jwt({"service": "caller", "aud": []})
        mw = self._middleware(service_name="svc-a")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_s2s_aud_as_substring_bypasses_check(self):
        """FINDING (not fixed, per test-only scope): PyJWT accepts `aud` as a
        bare string as well as a list. The middleware checks membership with
        `service_name not in payload.get("aud", [])`, which for a *string*
        aud performs a substring test rather than an exact-membership test.
        A token whose aud is "svc-a-extra" therefore satisfies
        `"svc-a" in "svc-a-extra"` and is treated as authorized for svc-a even
        though it was never issued a list containing svc-a. This test pins
        the current (insecure) behavior; it does not assert it is desirable.
        """
        tok = self._jwt({"service": "attacker", "aud": "svc-a-extra"})
        mw = self._middleware(service_name="svc-a")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_signing_key_returns_401(self):
        tok = self._jwt({"service": "caller", "aud": ["svc-a"]}, secret="attacker-key")
        mw = self._middleware(secret="real-secret")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unicode_service_name_round_trips(self):
        tok = self._jwt({"service": "调用者", "aud": ["svc-ünïcode"]})
        mw = self._middleware(service_name="svc-ünïcode")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        captured = {}

        async def next_fn(req):
            captured["svc"] = req.state.service
            return JSONResponse({"ok": True})

        resp = await mw.dispatch(request, next_fn)
        assert resp.status_code == 200
        assert captured["svc"] == "调用者"

    @pytest.mark.asyncio
    async def test_oversized_token_returns_401_not_crash(self):
        garbage = "a" * 100_000
        mw = self._middleware()
        request = Request(_make_scope(headers={"x-service-token": garbage}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_duplicate_service_token_headers_uses_first(self):
        good = self._jwt({"service": "caller", "aud": ["svc-a"]})
        bad = "not-a-jwt"
        raw = [(b"x-service-token", good.encode()), (b"x-service-token", bad.encode())]
        scope = {"type": "http", "method": "GET", "path": "/", "headers": raw, "query_string": b""}
        mw = self._middleware()
        request = Request(scope)
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 200


# ===========================================================================
# middleware/auth.py — AuthMiddleware: malformed Authorization header
# ===========================================================================

class TestAuthMiddlewareHeaderBoundaries:

    def _middleware(self, iam=None):
        from starlette.applications import Starlette
        from starlette.routing import Route

        from middleware.auth import AuthMiddleware

        async def endpoint(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", endpoint)])
        return AuthMiddleware(app, iam=iam or MagicMock())

    @pytest.mark.asyncio
    async def test_empty_string_header_treated_as_missing(self):
        mw = self._middleware()
        request = Request(_make_scope(headers={"authorization": ""}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "missing token"

    @pytest.mark.asyncio
    async def test_bearer_prefix_with_no_token_validates_empty_string(self):
        """`token.replace("Bearer ", "")` on the literal string "Bearer "
        yields "" -- this is not caught by the earlier `if not token` guard
        (which only rejects an absent header), so IAMClient.validate() is
        invoked with an empty string. Pinning this boundary explicitly."""
        iam = MagicMock()
        iam.validate = AsyncMock(return_value=None)
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer "}))
        resp = await mw.dispatch(request, _call_next)
        iam.validate.assert_called_once_with("")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_non_bearer_scheme_passed_through_unstripped(self):
        """A "Basic ..." (or any non-"Bearer " prefixed) header has nothing
        to strip, so the *entire* header value is forwarded to validate()."""
        iam = MagicMock()
        iam.validate = AsyncMock(return_value=None)
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Basic dXNlcjpwYXNz"}))
        await mw.dispatch(request, _call_next)
        iam.validate.assert_called_once_with("Basic dXNlcjpwYXNz")

    @pytest.mark.asyncio
    async def test_lowercase_bearer_scheme_not_stripped(self):
        """`.replace("Bearer ", "")` is case-sensitive; a lowercase "bearer "
        prefix is not recognized and is forwarded verbatim."""
        iam = MagicMock()
        iam.validate = AsyncMock(return_value=None)
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "bearer my-token"}))
        await mw.dispatch(request, _call_next)
        iam.validate.assert_called_once_with("bearer my-token")

    @pytest.mark.asyncio
    async def test_duplicate_authorization_headers_uses_first(self):
        iam = MagicMock()
        iam.validate = AsyncMock(return_value={"user_id": "u1"})
        mw = self._middleware(iam)
        raw = [(b"authorization", b"Bearer first-token"), (b"authorization", b"Bearer second-token")]
        scope = {"type": "http", "method": "GET", "path": "/", "headers": raw, "query_string": b""}
        request = Request(scope)
        await mw.dispatch(request, _call_next)
        iam.validate.assert_called_once_with("first-token")

    @pytest.mark.asyncio
    async def test_iam_validate_exception_propagates(self):
        """IAMClient.validate() has no internal timeout/network-error
        handling of its own (see TestIAMClientFailureModes below); the
        middleware likewise does not catch exceptions raised out of it, so a
        downstream failure (e.g. Redis or the IAM service being unreachable)
        surfaces as an unhandled exception rather than a clean 5xx. This test
        documents that fail path so a regression that silently swallowed it
        (fail-open) would be caught."""
        iam = MagicMock()
        iam.validate = AsyncMock(side_effect=ConnectionError("iam unreachable"))
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer tok"}))
        with pytest.raises(ConnectionError):
            await mw.dispatch(request, _call_next)


# ===========================================================================
# middleware/policy.py — PolicyMiddleware: fail-closed / malformed decisions
# ===========================================================================

class TestPolicyMiddlewareMalformedDecisions:

    def _middleware(self, policy=None):
        from starlette.applications import Starlette
        from starlette.routing import Route

        from middleware.policy import PolicyMiddleware

        async def endpoint(request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/", endpoint)])
        return PolicyMiddleware(app, policy=policy or MagicMock())

    @pytest.mark.asyncio
    async def test_decision_missing_allow_key_fails_closed(self):
        """An `{}` decision (no "allow" key at all) must be treated as a
        denial, not silently granted -- `.get("allow")` defaults to None,
        which is falsy, so this is correctly fail-closed today."""
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={})
        mw = self._middleware(policy)
        request = Request(_make_scope())
        with patch("middleware.policy.get_user", return_value={"user_id": "u1"}):
            resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_non_dict_decision_raises_instead_of_failing_closed(self):
        """FINDING (not fixed): if the policy engine ever returns something
        that isn't a dict (e.g. None, due to a malformed/empty upstream
        response), `decision.get("allow")` raises AttributeError instead of
        denying the request. This is unsafe *shaped* fallback behavior --
        it fails loudly (500) rather than silently open, but it is not the
        fail-closed 403 path exercised elsewhere. Documented, not fixed."""
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value=None)
        mw = self._middleware(policy)
        request = Request(_make_scope())
        with patch("middleware.policy.get_user", return_value={"user_id": "u1"}), \
             pytest.raises(AttributeError):
            await mw.dispatch(request, _call_next)

    @pytest.mark.asyncio
    async def test_policy_evaluate_exception_propagates(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(side_effect=TimeoutError("policy engine timeout"))
        mw = self._middleware(policy)
        request = Request(_make_scope())
        with patch("middleware.policy.get_user", return_value={"user_id": "u1"}), \
             pytest.raises(TimeoutError):
            await mw.dispatch(request, _call_next)


# ===========================================================================
# iam/client.py — IAMClient: type confusion & failure propagation
# ===========================================================================

class TestIAMClientFailureModes:

    async def _client(self):
        with patch("iam.client.redis") as mock_redis_mod, \
             patch("iam.client.httpx") as mock_httpx:
            mock_redis = AsyncMock()
            mock_redis_mod.from_url.return_value = mock_redis
            mock_http = AsyncMock()
            mock_httpx.AsyncClient.return_value = mock_http
            from iam.client import IAMClient
            client = IAMClient(base_url="http://auth:8001", redis_url="redis://localhost")
            return client, mock_redis, mock_http

    @pytest.mark.asyncio
    async def test_malformed_cached_json_raises(self):
        """A corrupted Redis cache entry (not valid JSON) is not caught --
        json.loads propagates a JSONDecodeError rather than falling back to
        a fresh remote validation. Documents an unsafe-fallback gap."""
        client, mock_redis, _ = await self._client()
        mock_redis.get = AsyncMock(return_value="{not-json")
        with pytest.raises(json.JSONDecodeError):
            await client.validate("tok")

    @pytest.mark.asyncio
    async def test_redis_get_exception_propagates(self):
        client, mock_redis, _ = await self._client()
        mock_redis.get = AsyncMock(side_effect=ConnectionError("redis down"))
        with pytest.raises(ConnectionError):
            await client.validate("tok")

    @pytest.mark.asyncio
    async def test_http_post_timeout_propagates(self):
        client, mock_redis, mock_http = await self._client()
        mock_redis.get = AsyncMock(return_value=None)
        mock_http.post = AsyncMock(side_effect=TimeoutError("iam service timeout"))
        with pytest.raises(TimeoutError):
            await client.validate("tok")

    @pytest.mark.asyncio
    async def test_missing_valid_key_returns_none(self):
        """`data.get("valid")` with no "valid" key at all must deny (falsy
        default), same as an explicit False -- fail-closed on missing data."""
        client, mock_redis, mock_http = await self._client()
        mock_redis.get = AsyncMock(return_value=None)
        mock_resp = MagicMock(status_code=200, json=lambda: {"user_id": "u1"})
        mock_http.post = AsyncMock(return_value=mock_resp)
        result = await client.validate("tok")
        assert result is None

    @pytest.mark.asyncio
    async def test_truthy_string_valid_field_treated_as_valid(self):
        """FINDING (not fixed): `if not data.get("valid")` uses Python
        truthiness, not a strict boolean check. A non-empty string such as
        "false" is truthy, so a malformed upstream response encoding
        `valid` as the *string* "false" is (incorrectly) treated as a
        successful validation. This documents the type-confusion gap; it
        does not assert the behavior is desirable."""
        client, mock_redis, mock_http = await self._client()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock()
        payload = {"valid": "false", "user_id": "attacker-controlled"}
        mock_resp = MagicMock(status_code=200, json=lambda: payload)
        mock_http.post = AsyncMock(return_value=mock_resp)
        result = await client.validate("tok")
        assert result == payload

    @pytest.mark.asyncio
    async def test_valid_as_zero_is_treated_as_invalid(self):
        """Conversely, `valid: 0` (falsy) is correctly denied -- shown here
        for contrast with the string-"false" type-confusion case above."""
        client, mock_redis, mock_http = await self._client()
        mock_redis.get = AsyncMock(return_value=None)
        mock_resp = MagicMock(status_code=200, json=lambda: {"valid": 0})
        mock_http.post = AsyncMock(return_value=mock_resp)
        result = await client.validate("tok")
        assert result is None


# ===========================================================================
# policy/client.py — PolicyClient: malformed external responses
# ===========================================================================

class TestPolicyClientMalformedResponses:

    @pytest.mark.asyncio
    async def test_non_json_response_propagates(self):
        with patch("policy.client.httpx") as mock_httpx:
            mock_http = AsyncMock()
            mock_httpx.AsyncClient.return_value = mock_http
            from policy.client import PolicyClient
            client = PolicyClient(base_url="http://policy:8002")
            mock_resp = MagicMock()
            mock_resp.json.side_effect = ValueError("not json")
            client.http.post = AsyncMock(return_value=mock_resp)
            with pytest.raises(ValueError):
                await client.evaluate(user={}, path="/x", method="GET")

    @pytest.mark.asyncio
    async def test_non_dict_json_response_passed_through(self):
        """evaluate() has no validation of the decoded body's shape -- a
        list/scalar response is returned to the caller as-is, which is what
        later causes PolicyMiddleware's `.get("allow")` to raise (see
        test_non_dict_decision_raises_instead_of_failing_closed)."""
        with patch("policy.client.httpx") as mock_httpx:
            mock_http = AsyncMock()
            mock_httpx.AsyncClient.return_value = mock_http
            from policy.client import PolicyClient
            client = PolicyClient(base_url="http://policy:8002")
            mock_resp = MagicMock(json=lambda: ["unexpected", "list"])
            client.http.post = AsyncMock(return_value=mock_resp)
            result = await client.evaluate(user={}, path="/x", method="GET")
            assert result == ["unexpected", "list"]

    @pytest.mark.asyncio
    async def test_http_post_network_failure_propagates(self):
        with patch("policy.client.httpx") as mock_httpx:
            mock_http = AsyncMock()
            mock_httpx.AsyncClient.return_value = mock_http
            from policy.client import PolicyClient
            client = PolicyClient(base_url="http://policy:8002")
            client.http.post = AsyncMock(side_effect=ConnectionError("policy engine unreachable"))
            with pytest.raises(ConnectionError):
                await client.evaluate(user={}, path="/x", method="GET")


# ===========================================================================
# audit/client.py — AuditClient: serialization boundary
# ===========================================================================

class TestAuditClientSerializationBoundary:

    @pytest.mark.asyncio
    async def test_non_serializable_event_raises_typeerror(self):
        mock_redis = AsyncMock()
        with patch("audit.client.redis") as mock_redis_module:
            mock_redis_module.from_url.return_value = mock_redis
            from audit.client import AuditClient
            ac = AuditClient(redis_url="redis://localhost")
            ac.redis = mock_redis

        class Unserializable:
            pass

        with pytest.raises(TypeError):
            await ac.emit({"event_type": "x", "bad_field": Unserializable()})

    @pytest.mark.asyncio
    async def test_redis_xadd_failure_propagates(self):
        mock_redis = AsyncMock()
        mock_redis.xadd = AsyncMock(side_effect=ConnectionError("redis unreachable"))
        with patch("audit.client.redis") as mock_redis_module:
            mock_redis_module.from_url.return_value = mock_redis
            from audit.client import AuditClient
            ac = AuditClient(redis_url="redis://localhost")
            ac.redis = mock_redis

        with pytest.raises(ConnectionError):
            await ac.emit({"event_type": "x"})


# ===========================================================================
# core/config.py — environment-driven configuration
# ===========================================================================

class TestSecurityConfigEnvironmentHandling:

    def test_env_overrides_are_picked_up_on_import(self, monkeypatch):
        """SecurityConfig reads os.getenv at class-definition time, so an
        environment override must be visible to a fresh import -- this is
        the mechanism operators rely on to point at real IAM/policy/redis
        endpoints instead of the insecure localhost/dev-secret defaults."""
        monkeypatch.setenv("IAM_BASE_URL", "https://iam.internal.example")
        monkeypatch.setenv("POLICY_BASE_URL", "https://policy.internal.example")
        monkeypatch.setenv("REDIS_URL", "redis://redis.internal:6380")
        monkeypatch.setenv("SERVICE_NAME", "omnibioai-tes")
        monkeypatch.setenv("SERVICE_SECRET", "prod-secret-value")

        import core.config as config_mod
        importlib.reload(config_mod)
        try:
            assert config_mod.SecurityConfig.IAM_BASE_URL == "https://iam.internal.example"
            assert config_mod.SecurityConfig.POLICY_BASE_URL == "https://policy.internal.example"
            assert config_mod.SecurityConfig.REDIS_URL == "redis://redis.internal:6380"
            assert config_mod.SecurityConfig.SERVICE_NAME == "omnibioai-tes"
            assert config_mod.SecurityConfig.SERVICE_SECRET == "prod-secret-value"
        finally:
            monkeypatch.delenv("IAM_BASE_URL", raising=False)
            monkeypatch.delenv("POLICY_BASE_URL", raising=False)
            monkeypatch.delenv("REDIS_URL", raising=False)
            monkeypatch.delenv("SERVICE_NAME", raising=False)
            monkeypatch.delenv("SERVICE_SECRET", raising=False)
            importlib.reload(config_mod)

    def test_defaults_are_restored_after_env_cleared(self):
        """Sanity check that the reload in the previous test actually
        restores the documented insecure-but-functional defaults, so this
        test's baseline assumptions (and other tests relying on defaults)
        aren't left polluted by env-var leakage between tests."""
        import core.config as config_mod
        assert config_mod.SecurityConfig.SERVICE_SECRET == "dev-secret"
        assert config_mod.SecurityConfig.IAM_BASE_URL == "http://omnibioai-auth:8000"
