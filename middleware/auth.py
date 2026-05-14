from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from omnibioai_security_sdk.iam.client import IAMClient
from omnibioai_security_sdk.core.context import set_user


class AuthMiddleware(BaseHTTPMiddleware):

    def __init__(self, app, iam: IAMClient):
        super().__init__(app)
        self.iam = iam

    async def dispatch(self, request, call_next):

        token = request.headers.get("Authorization")

        if not token:
            return JSONResponse({"error": "missing token"}, 401)

        token = token.replace("Bearer ", "")

        user = await self.iam.validate(token)

        if not user:
            return JSONResponse({"error": "unauthorized"}, 401)

        set_user(user)
        request.state.user = user

        return await call_next(request)