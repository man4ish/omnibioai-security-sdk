import httpx
import json
import redis.asyncio as redis


class IAMClient:
    def __init__(self, base_url: str, redis_url: str):
        self.base_url = base_url
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.http = httpx.AsyncClient(timeout=2)

    async def validate(self, token: str):
        cache_key = f"iam:{token}"

        cached = await self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        res = await self.http.post(
            f"{self.base_url}/auth/validate",
            json={"token": token},
        )

        if res.status_code != 200:
            return None

        data = res.json()

        if not data.get("valid"):
            return None

        await self.redis.setex(cache_key, 300, json.dumps(data))

        return data