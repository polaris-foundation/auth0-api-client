from unittest.mock import Mock

import pytest
import requests
from pytest_mock import MockFixture

from auth0_api_client.errors import Auth0ConnectionError
from auth0_api_client.jwt import get_auth0_jwt_for_client, get_auth0_jwt_for_user


class TestJwt:
    def test_get_auth0_jwt_for_client_success(self, mocker: MockFixture) -> None:
        expected = "some_token"
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(spec=requests.Response, status_code=200, headers={})
        mock_jwt_response.json.return_value = {"access_token": expected}
        mock_post.return_value = mock_jwt_response
        actual: str = get_auth0_jwt_for_client(
            client_id="test", client_secret="test", audience="test"
        )
        assert actual == expected

    def test_get_auth0_jwt_for_client_failure(self, mocker: MockFixture) -> None:
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(spec=requests.Response, status_code=404, headers={})
        mock_jwt_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_post.return_value = mock_jwt_response
        with pytest.raises(Auth0ConnectionError):
            get_auth0_jwt_for_client(
                client_id="test",
                client_secret="test",
                audience="test",
            )

    def test_get_auth0_jwt_for_user_success(self, mocker: MockFixture) -> None:
        expected = "some_token"
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(spec=requests.Response, status_code=200, headers={})
        mock_jwt_response.json.return_value = {"access_token": expected}
        mock_post.return_value = mock_jwt_response
        actual: str = get_auth0_jwt_for_user(username="test", password="test")
        assert actual == expected

    def test_get_auth0_jwt_for_user_failure(self, mocker: MockFixture) -> None:
        mock_post: Mock = mocker.patch("requests.post")
        mock_jwt_response = Mock(spec=requests.Response, status_code=404, headers={})
        mock_jwt_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_post.return_value = mock_jwt_response
        with pytest.raises(Auth0ConnectionError):
            get_auth0_jwt_for_user(
                username="test",
                password="test",
            )
