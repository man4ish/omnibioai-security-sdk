import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_async_redis():
    return AsyncMock()


@pytest.fixture
def mock_http():
    return AsyncMock()


@pytest.fixture
def iam_client_setup(mock_async_redis, mock_http):
    with patch("iam.client.redis") as mock_redis_module, \
         patch("iam.client.httpx") as mock_httpx:
        mock_redis_module.from_url.return_value = mock_async_redis
        mock_httpx.AsyncClient.return_value = mock_http
        from iam.client import IAMClient
        client = IAMClient(base_url="http://test-iam", redis_url="redis://localhost")
        client.redis = mock_async_redis
        client.http = mock_http
        yield client, mock_async_redis, mock_http


@pytest.fixture
def policy_client_setup(mock_http):
    with patch("policy.client.httpx") as mock_httpx:
        mock_httpx.AsyncClient.return_value = mock_http
        from policy.client import PolicyClient
        client = PolicyClient(base_url="http://test-policy")
        client.http = mock_http
        yield client, mock_http
