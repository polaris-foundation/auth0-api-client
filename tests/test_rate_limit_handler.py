from functools import partial
from unittest.mock import Mock, call

import pytest
import requests
from pytest_mock import MockFixture

from auth0_api_client import rate_limit_handler
from auth0_api_client.errors import Auth0ConnectionError
from auth0_api_client.jwt import get_auth0_jwt_for_client, get_auth0_jwt_for_user
from auth0_api_client.rate_limit_handler import retry_if_too_many_requests, time


class TestRateLimitHandler:
    @pytest.fixture
    def mock_sleep(self, mocker: MockFixture) -> Mock:
        sleep: Mock = mocker.patch.object(time, "sleep")
        return sleep

    @pytest.mark.parametrize("user_type", ["user", "client"])
    def test_prevent_or_handle_200(self, mocker: MockFixture, user_type: str) -> None:
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(
            spec=requests.Response,
            status_code=200,
            headers={"X-RateLimit-Reset": time.time() + 1, "X-RateLimit-Remaining": 0},
            json=lambda: {"access_token": "abrakadabra"},
        )
        mock_post.return_value = mock_jwt_response
        if user_type == "client":
            jwt = get_auth0_jwt_for_client(
                client_id="test",
                client_secret="test",
                audience="test",
            )
        else:
            jwt = get_auth0_jwt_for_user(username="test", password="test")

        assert jwt == "abrakadabra", jwt
        mock_post.assert_called_once()

    @pytest.mark.parametrize("user_type", ["user", "client"])
    def test_prevent_or_handle_429_backoff(
        self, mocker: MockFixture, user_type: str, mock_sleep: Mock
    ) -> None:
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(
            spec=requests.Response,
            status_code=429,
            headers={"X-RateLimit-Reset": time.time() + 1, "X-RateLimit-Remaining": 0},
            json=lambda: {"error_description": ""},
        )
        mock_jwt_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=429), "too many requests"
        )
        mock_post.return_value = mock_jwt_response
        with pytest.raises(Auth0ConnectionError):
            if user_type == "client":
                get_auth0_jwt_for_client(
                    client_id="test",
                    client_secret="test",
                    audience="test",
                )
            else:
                get_auth0_jwt_for_user(username="test", password="test")

        assert mock_post.call_count == 5
        assert mock_sleep.call_count == 5
        mock_sleep.assert_has_calls(
            [call(1), call(2), call(4), call(8), call(16)], any_order=False
        )

    @pytest.mark.parametrize("user_type", ["user", "client"])
    def test_prevent_or_handle_429_non_backoff(
        self, mocker: MockFixture, user_type: str, mock_sleep: Mock
    ) -> None:
        from auth0_api_client.rate_limit_handler import time as time_

        mocker.patch.object(
            rate_limit_handler,
            "retry_if_too_many_requests",
            partial(retry_if_too_many_requests, backoff_factor=0),
        )
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(
            spec=requests.Response,
            status_code=429,
            headers={"X-RateLimit-Reset": time.time() + 1, "X-RateLimit-Remaining": 0},
            json=lambda: {"error_description": ""},
        )
        mock_jwt_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=429), "too many requests"
        )
        mock_post.return_value = mock_jwt_response

        with pytest.raises(Auth0ConnectionError):
            if user_type == "client":
                get_auth0_jwt_for_client(
                    client_id="test",
                    client_secret="test",
                    audience="test",
                )
            else:
                get_auth0_jwt_for_user(username="test", password="test")

        assert mock_post.call_count == 5
        assert mock_sleep.call_count == 5
        mock_sleep.assert_has_calls([call(1)] * 5, any_order=True)
