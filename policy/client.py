import httpx


class PolicyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.http = httpx.AsyncClient(timeout=2)

    async def evaluate(self, user, path: str, method: str):
        res = await self.http.post(
            f"{self.base_url}/evaluate",
            json={
                "user": user,
                "path": path,
                "method": method,
            },
        )
        return res.json()