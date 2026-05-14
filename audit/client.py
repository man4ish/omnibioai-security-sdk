import json
import redis.asyncio as redis


class AuditClient:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.stream = "audit:events"

    async def emit(self, event: dict):
        await self.redis.xadd(
            self.stream,
            {"data": json.dumps(event)},
            maxlen=1_000_000,
            approximate=True,
        )