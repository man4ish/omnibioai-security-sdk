from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from omnibioai_security_sdk.policy.client import PolicyClient
from omnibioai_security_sdk.core.context import get_user


class PolicyMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, policy: PolicyClient):
        super().__init__(app)
        self.policy = policy

    async def dispatch(self, request, call_next):

        user = get_user()

        decision = await self.policy.evaluate(
            user=user,
            path=request.url.path,
            method=request.method,
        )

        if not decision.get("allow"):
            return JSONResponse(
                {"error": "forbidden", "reason": decision.get("reason")},
                status_code=403,
            )

        return await call_next(request)