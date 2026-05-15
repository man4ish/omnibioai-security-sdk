"""
Tests for policy/client.py — PolicyClient.evaluate()
"""
import pytest
from unittest.mock import AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# PolicyClient.evaluate — allow / deny
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evaluate_allow_decision(policy_client_setup):
    client, mock_http = policy_client_setup
    mock_http.post = AsyncMock(return_value=MagicMock(
        json=lambda: {"allow": True, "reason": "access granted"}
    ))

    result = await client.evaluate(
        user={"user_id": "u1", "roles": ["researcher"]},
        path="/api/tes/submit",
        method="POST",
    )

    assert result["allow"] is True
    assert result["reason"] == "access granted"


@pytest.mark.asyncio
async def test_evaluate_deny_decision(policy_client_setup):
    client, mock_http = policy_client_setup
    mock_http.post = AsyncMock(return_value=MagicMock(
        json=lambda: {"allow": False, "reason": "forbidden"}
    ))

    result = await client.evaluate(
        user={"user_id": "u2", "roles": []},
        path="/api/dataset/delete",
        method="DELETE",
    )

    assert result["allow"] is False
    assert "forbidden" in result["reason"]


@pytest.mark.asyncio
async def test_evaluate_posts_to_correct_url(policy_client_setup):
    client, mock_http = policy_client_setup
    mock_response = MagicMock(json=lambda: {"allow": True})
    mock_http.post = AsyncMock(return_value=mock_response)

    await client.evaluate(user={}, path="/some/path", method="GET")

    call_url = mock_http.post.call_args[0][0]
    assert call_url == "http://test-policy/evaluate"


@pytest.mark.asyncio
async def test_evaluate_sends_user_path_method(policy_client_setup):
    client, mock_http = policy_client_setup
    mock_response = MagicMock(json=lambda: {"allow": True})
    mock_http.post = AsyncMock(return_value=mock_response)

    user_obj = {"user_id": "u3", "roles": ["admin"]}
    await client.evaluate(user=user_obj, path="/resource", method="PUT")

    call_json = mock_http.post.call_args[1]["json"]
    assert call_json["user"] == user_obj
    assert call_json["path"] == "/resource"
    assert call_json["method"] == "PUT"


@pytest.mark.asyncio
async def test_evaluate_returns_raw_json(policy_client_setup):
    client, mock_http = policy_client_setup
    payload = {"allow": True, "reason": "ok", "extra": "data"}
    mock_http.post = AsyncMock(return_value=MagicMock(json=lambda: payload))

    result = await client.evaluate(user={}, path="/", method="GET")

    assert result == payload
