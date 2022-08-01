from unittest.mock import Mock

import pytest
import requests
from pytest_mock import MockFixture
from requests_mock import Mocker

from auth0_api_client import auth0_config
from auth0_api_client.errors import Auth0ConnectionError, Auth0OperationError
from auth0_api_client.mgmt import (
    _get_connection_id,
    get_mgmt_jwt,
    request_password_reset,
)


class TestMgmt:
    def test_get_mgmt_jwt_failure(self, mocker: MockFixture) -> None:
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            side_effect=Auth0ConnectionError(),
        )
        with pytest.raises(Auth0ConnectionError):
            get_mgmt_jwt()

    def test_get_mgmt_jwt_success(self, mocker: MockFixture) -> None:
        expected = "jwt_header.payload.secret_signature"
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client", return_value=expected
        )
        actual = get_mgmt_jwt()
        assert actual == expected

    def test_get_connection_id_success(
        self, requests_mock: Mocker, mocker: MockFixture
    ) -> None:
        auth0_config["PROXY_URL"] = "https://training-test.sensynehealth.com"
        expected = "test_connection_id"
        mock_get_page1: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=0&per_page=50",
            json=[
                {"id": expected, "name": "training-test-users"},
                {"id": "other_connection_id", "name": "other-users"},
            ],
        )
        mock_get_page2: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=1&per_page=50", json=[]
        )
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        actual = _get_connection_id(_jwt="")
        assert actual == expected
        assert mock_get_page1.call_count == 1
        assert mock_get_page2.call_count == 1

    def test_get_connection_id_failure(
        self, requests_mock: Mocker, mocker: MockFixture
    ) -> None:
        auth0_config["PROXY_URL"] = "https://test.sensynehealth.com"
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_get_page1: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=0&per_page=50", status_code=404
        )
        with pytest.raises(Auth0ConnectionError):
            _get_connection_id(_jwt="")
        assert mock_get_page1.call_count == 1

    def test_get_connection_id_unknown(
        self, requests_mock: Mocker, mocker: MockFixture
    ) -> None:
        auth0_config["PROXY_URL"] = "https://test.sensynehealth.com"
        mock_get_page1: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=0&per_page=50",
            json=[
                {"id": "some_id_1", "name": "other1-users"},
                {"id": "some_id_2", "name": "other2-users"},
            ],
        )
        mock_get_page2: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=1&per_page=50", json=[]
        )
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        with pytest.raises(Auth0OperationError):
            _get_connection_id(_jwt="")
        assert mock_get_page1.call_count == 1
        assert mock_get_page2.call_count == 1

    def test_request_password_reset_success(
        self, requests_mock: Mocker, mocker: MockFixture
    ) -> None:
        expected = "http://someurl.com"
        mock_get_page1: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=0&per_page=50",
            json=[{"id": expected, "name": "test-users"}],
        )
        mock_get_page2: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=1&per_page=50", json=[]
        )
        mock_post: Mock = mocker.patch("requests.post")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_reset_response = Mock(spec=requests.Response, status_code=200)
        mock_reset_response.json.return_value = {"ticket": expected}
        mock_post.return_value = mock_reset_response
        actual = request_password_reset("email@email.email")
        assert actual == expected
        assert mock_get_page1.call_count == 1
        assert mock_get_page2.call_count == 1

    def test_request_password_reset_failure(
        self, requests_mock: Mocker, mocker: MockFixture
    ) -> None:
        expected = "http://someurl.com"
        mock_get_page1: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=0&per_page=50",
            json=[{"id": expected, "name": "test-users"}],
        )
        mock_get_page2: Mock = requests_mock.get(
            "https://somefakeurl/api/v2/connections?page=1&per_page=50", json=[]
        )
        mock_post: Mock = mocker.patch("requests.post")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_reset_response = Mock(spec=requests.Response, status_code=404)
        mock_reset_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_post.return_value = mock_reset_response
        with pytest.raises(Auth0ConnectionError):
            request_password_reset(email_address="email@email.email")
        assert mock_get_page1.call_count == 1
        assert mock_get_page2.call_count == 1
