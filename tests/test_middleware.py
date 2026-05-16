"""tests/test_middleware.py — covers middleware/auth.py, middleware/policy.py, middleware/s2s.py

The middleware modules import from `omnibioai_security_sdk.*` (the installed-package path),
but the repo exposes modules directly at the root (iam/, core/, policy/).
We bridge this by wiring sys.modules before importing the middleware files.
"""
from __future__ import annotations

import json
import sys
import types
import importlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.applications import Starlette
from starlette.routing import Route


# ---------------------------------------------------------------------------
# Bridge: make `omnibioai_security_sdk.*` resolve to local root modules
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
        # also set as attribute on the parent
        parent = root_ns
        for part in parts[:-1]:
            parent = sys.modules.get(f"omnibioai_security_sdk.{part}", parent)
        setattr(parent, parts[-1], real)
    sys.modules["omnibioai_security_sdk"] = root_ns


_ensure_sdk_namespace()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

async def _dummy_endpoint(request):
    return JSONResponse({"ok": True})


async def _call_next(request):
    return JSONResponse({"ok": True})


def _make_scope(method="GET", path="/", headers=None):
    raw = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    return {"type": "http", "method": method, "path": path, "headers": raw, "query_string": b""}


def _body(response):
    return json.loads(response.body)


# ===========================================================================
# middleware/auth.py — AuthMiddleware
# ===========================================================================

class TestAuthMiddleware:

    def _middleware(self, iam=None):
        from middleware.auth import AuthMiddleware
        app = Starlette(routes=[Route("/", _dummy_endpoint)])
        return AuthMiddleware(app, iam=iam or MagicMock())

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self):
        mw = self._middleware()
        request = Request(_make_scope())
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "missing token"

    @pytest.mark.asyncio
    async def test_invalid_token_none_user_returns_401(self):
        iam = MagicMock()
        iam.validate = AsyncMock(return_value=None)
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer bad"}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "unauthorized"

    @pytest.mark.asyncio
    async def test_valid_token_calls_next_and_returns_200(self):
        iam = MagicMock()
        iam.validate = AsyncMock(return_value={"user_id": "u1"})
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer good-tok"}))
        called = {"n": 0}

        async def next_fn(req):
            called["n"] += 1
            return JSONResponse({"ok": True})

        resp = await mw.dispatch(request, next_fn)
        assert called["n"] == 1
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_prefix_stripped(self):
        iam = MagicMock()
        iam.validate = AsyncMock(return_value={"user_id": "u1"})
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer my-token-123"}))
        await mw.dispatch(request, _call_next)
        iam.validate.assert_called_once_with("my-token-123")

    @pytest.mark.asyncio
    async def test_user_attached_to_request_state(self):
        user = {"user_id": "u42", "role": "admin"}
        iam = MagicMock()
        iam.validate = AsyncMock(return_value=user)
        mw = self._middleware(iam)
        request = Request(_make_scope(headers={"authorization": "Bearer tok"}))
        captured = {}

        async def next_fn(req):
            captured["user"] = req.state.user
            return JSONResponse({"ok": True})

        await mw.dispatch(request, next_fn)
        assert captured["user"] == user

    @pytest.mark.asyncio
    async def test_set_user_context_called(self):
        iam = MagicMock()
        iam.validate = AsyncMock(return_value={"user_id": "ctx-u"})
        with patch("middleware.auth.set_user") as mock_set:
            mw = self._middleware(iam)
            request = Request(_make_scope(headers={"authorization": "Bearer ctx-tok"}))
            await mw.dispatch(request, _call_next)
            mock_set.assert_called_once_with({"user_id": "ctx-u"})

    @pytest.mark.asyncio
    async def test_missing_token_does_not_call_validate(self):
        iam = MagicMock()
        iam.validate = AsyncMock()
        mw = self._middleware(iam)
        request = Request(_make_scope())
        await mw.dispatch(request, _call_next)
        iam.validate.assert_not_called()


# ===========================================================================
# middleware/policy.py — PolicyMiddleware
# ===========================================================================

class TestPolicyMiddleware:

    def _middleware(self, policy=None):
        from middleware.policy import PolicyMiddleware
        app = Starlette(routes=[Route("/", _dummy_endpoint)])
        return PolicyMiddleware(app, policy=policy or MagicMock())

    @pytest.mark.asyncio
    async def test_allow_decision_passes_through(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={"allow": True})
        mw = self._middleware(policy)
        request = Request(_make_scope(method="GET", path="/data"))
        reached = {"n": 0}

        async def next_fn(req):
            reached["n"] += 1
            return JSONResponse({"data": "secret"})

        with patch("middleware.policy.get_user", return_value={"user_id": "u1"}):
            resp = await mw.dispatch(request, next_fn)

        assert reached["n"] == 1
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_deny_decision_returns_403(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={"allow": False, "reason": "no perms"})
        mw = self._middleware(policy)
        request = Request(_make_scope(method="POST", path="/admin"))

        with patch("middleware.policy.get_user", return_value={"user_id": "u2"}):
            resp = await mw.dispatch(request, _call_next)

        assert resp.status_code == 403
        body = _body(resp)
        assert body["error"] == "forbidden"
        assert body["reason"] == "no perms"

    @pytest.mark.asyncio
    async def test_evaluate_called_with_correct_args(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={"allow": True})
        mw = self._middleware(policy)
        user = {"user_id": "u3", "role": "editor"}
        request = Request(_make_scope(method="DELETE", path="/resource/99"))

        with patch("middleware.policy.get_user", return_value=user):
            await mw.dispatch(request, _call_next)

        policy.evaluate.assert_called_once_with(user=user, path="/resource/99", method="DELETE")

    @pytest.mark.asyncio
    async def test_deny_without_reason_key_returns_none(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={"allow": False})
        mw = self._middleware(policy)
        request = Request(_make_scope())

        with patch("middleware.policy.get_user", return_value={}):
            resp = await mw.dispatch(request, _call_next)

        assert resp.status_code == 403
        assert _body(resp)["reason"] is None

    @pytest.mark.asyncio
    async def test_allow_false_does_not_call_next(self):
        policy = MagicMock()
        policy.evaluate = AsyncMock(return_value={"allow": False, "reason": "denied"})
        mw = self._middleware(policy)
        request = Request(_make_scope())
        reached = {"n": 0}

        async def next_fn(req):
            reached["n"] += 1
            return JSONResponse({"ok": True})

        with patch("middleware.policy.get_user", return_value={}):
            await mw.dispatch(request, next_fn)

        assert reached["n"] == 0


# ===========================================================================
# middleware/s2s.py — ServiceAuthMiddleware
# ===========================================================================

class TestServiceAuthMiddleware:

    def _middleware(self, secret="secret", service_name="svc-a"):
        from middleware.s2s import ServiceAuthMiddleware
        app = Starlette(routes=[Route("/", _dummy_endpoint)])
        return ServiceAuthMiddleware(app, secret=secret, service_name=service_name)

    def _jwt(self, payload, secret="secret"):
        import jwt as _jwt
        return _jwt.encode(payload, secret, algorithm="HS256")

    @pytest.mark.asyncio
    async def test_missing_header_returns_401(self):
        mw = self._middleware()
        request = Request(_make_scope())
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "missing service token"

    @pytest.mark.asyncio
    async def test_malformed_token_returns_401(self):
        mw = self._middleware()
        request = Request(_make_scope(headers={"x-service-token": "not-jwt"}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "invalid service token"

    @pytest.mark.asyncio
    async def test_wrong_secret_returns_401(self):
        tok = self._jwt({"service": "caller"}, secret="correct")
        mw = self._middleware(secret="wrong")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 401
        assert _body(resp)["error"] == "invalid service token"

    @pytest.mark.asyncio
    async def test_service_not_in_audience_returns_403(self):
        # Token without aud field → payload.get("aud", []) == [] → 403
        tok = self._jwt({"service": "caller"})
        mw = self._middleware(service_name="svc-a")
        request = Request(_make_scope(headers={"x-service-token": tok}))
        resp = await mw.dispatch(request, _call_next)
        assert resp.status_code == 403
        assert _body(resp)["error"] == "service not allowed"

    @pytest.mark.asyncio
    async def test_service_in_audience_calls_next(self):
        with patch("middleware.s2s.jwt.decode", return_value={"service": "caller", "aud": ["svc-a"]}):
            mw = self._middleware(service_name="svc-a")
            request = Request(_make_scope(headers={"x-service-token": "any-token"}))
            reached = {"n": 0}

            async def next_fn(req):
                reached["n"] += 1
                return JSONResponse({"ok": True})

            resp = await mw.dispatch(request, next_fn)
            assert reached["n"] == 1
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_service_set_on_request_state(self):
        with patch("middleware.s2s.jwt.decode", return_value={"service": "upstream", "aud": ["svc-a"]}):
            mw = self._middleware(service_name="svc-a")
            request = Request(_make_scope(headers={"x-service-token": "any"}))
            captured = {}

            async def next_fn(req):
                captured["svc"] = req.state.service
                return JSONResponse({"ok": True})

            await mw.dispatch(request, next_fn)
            assert captured["svc"] == "upstream"

    @pytest.mark.asyncio
    async def test_middleware_stores_secret_and_service_name(self):
        from middleware.s2s import ServiceAuthMiddleware
        app = Starlette(routes=[Route("/", _dummy_endpoint)])
        mw = ServiceAuthMiddleware(app, secret="my-sec", service_name="my-svc")
        assert mw.secret == "my-sec"
        assert mw.service_name == "my-svc"
