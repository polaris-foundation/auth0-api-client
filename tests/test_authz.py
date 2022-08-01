from typing import List
from unittest.mock import Mock

import pytest
import requests
from pytest_mock import MockFixture

from auth0_api_client.authz import (
    _get_auth0_auth_groups,
    add_user_to_authz_groups,
    get_permissions_for_group,
    remove_user_from_authz_groups,
)
from auth0_api_client.errors import Auth0ConnectionError, Auth0OperationError
from auth0_api_client.models.permission import Permission


class TestAuthz:
    def test_get_permissions_for_group_success(self, mocker: MockFixture) -> None:
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_roles_response = Mock(spec=requests.Response, status_code=200)
        mock_roles_response.json.return_value = SAMPLE_ROLES
        mock_permissions_response = Mock(spec=requests.Response, status_code=200)
        mock_permissions_response.json.return_value = SAMPLE_PERMISSIONS
        mock_get.side_effect = [
            mock_permissions_response,
            mock_roles_response,
            mock_groups_response,
        ]
        actual: List[Permission] = get_permissions_for_group(group_name="System")
        assert len(actual) == 2
        assert actual[0].name == "write:elf"
        assert actual[1].name == "write:dwarf"

    def test_get_permissions_for_group_unknown_group(self, mocker: MockFixture) -> None:
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_roles_response = Mock(spec=requests.Response, status_code=200)
        mock_roles_response.json.return_value = SAMPLE_ROLES
        mock_permissions_response = Mock(spec=requests.Response, status_code=200)
        mock_permissions_response.json.return_value = SAMPLE_PERMISSIONS
        mock_get.side_effect = [
            mock_permissions_response,
            mock_roles_response,
            mock_groups_response,
        ]
        actual: List[Permission] = get_permissions_for_group(group_name="Unknown Group")
        assert len(actual) == 0

    def test_get_permissions_for_group_jwt_failure(self, mocker: MockFixture) -> None:
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_jwt_response = Mock(spec=requests.Response, status_code=200)
        mock_jwt_response.json.return_value = {
            "access_token": "jwt_header.payload.secret_signature"
        }
        mock_groups_response = Mock(spec=requests.Response, status_code=404)
        mock_groups_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_get.return_value = mock_groups_response
        with pytest.raises(Auth0ConnectionError):
            get_permissions_for_group(group_name="System")

    def test_get_permissions_for_group_authz_failure(self, mocker: MockFixture) -> None:
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            side_effect=Auth0ConnectionError(),
        )
        with pytest.raises(Auth0ConnectionError):
            get_permissions_for_group(group_name="System")

    def test_add_user_to_authz_groups_success(self, mocker: MockFixture) -> None:
        mock_patch: Mock = mocker.patch("requests.patch")
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_get.return_value = mock_groups_response
        add_user_to_authz_groups(user_id="test", group_names=["GDM Patient"])
        mock_patch.assert_called_once()

    def test_get_auth0_auth_groups_failure(self, mocker: MockFixture) -> None:
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=404)
        mock_groups_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_get.return_value = mock_groups_response
        with pytest.raises(Auth0ConnectionError):
            _get_auth0_auth_groups(_jwt="jwt_header.payload.secret_signature")

    def test_add_user_to_authz_groups_failure(self, mocker: MockFixture) -> None:
        mock_patch: Mock = mocker.patch("requests.patch")
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_patch_response = Mock(spec=requests.Response, status_code=404)
        mock_patch_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_get.return_value = mock_groups_response
        mock_patch.return_value = mock_patch_response
        with pytest.raises(Auth0ConnectionError):
            add_user_to_authz_groups(
                user_id="test",
                group_names=["GDM Patient"],
            )

    def test_add_user_to_authz_groups_unknown(self, mocker: MockFixture) -> None:
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = {"groups": []}
        mock_get.return_value = mock_groups_response
        with pytest.raises(Auth0OperationError):
            add_user_to_authz_groups(
                user_id="test",
                group_names=["GDM Patient"],
            )

    def test_remove_user_from_authz_groups_success(self, mocker: MockFixture) -> None:
        mock_delete: Mock = mocker.patch("requests.delete")
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_get.return_value = mock_groups_response
        remove_user_from_authz_groups(user_id="test", group_names=["GDM Patient"])
        mock_delete.assert_called_once()

    def test_remove_user_from_authz_groups_failure(self, mocker: MockFixture) -> None:
        mock_delete: Mock = mocker.patch("requests.delete")
        mock_get: Mock = mocker.patch("requests.get")
        mocker.patch(
            "auth0_api_client.jwt.get_auth0_jwt_for_client",
            return_value="jwt_header.payload.secret_signature",
        )
        mock_groups_response = Mock(spec=requests.Response, status_code=200)
        mock_groups_response.json.return_value = SAMPLE_GROUPS
        mock_delete_response = Mock(spec=requests.Response, status_code=404)
        mock_delete_response.raise_for_status.side_effect = requests.HTTPError(
            Mock(status=404), "not found"
        )
        mock_get.return_value = mock_groups_response
        mock_delete.return_value = mock_delete_response
        with pytest.raises(Auth0ConnectionError):
            remove_user_from_authz_groups(
                user_id="test",
                group_names=["GDM Patient"],
            )


SAMPLE_GROUPS = {
    "groups": [
        {
            "_id": "id_group_gdm_patient",
            "description": "GDM Patient",
            "mappings": [],
            "members": [],
            "name": "GDM Patient",
            "roles": ["id_role_gdm_patient_same", "id_role_gdm_patient_different"],
        },
        {
            "_id": "id_group_system",
            "description": "System",
            "mappings": [],
            "members": [],
            "name": "System",
            "roles": ["id_role_system_same", "id_role_system_different"],
        },
    ]
}

SAMPLE_ROLES = {
    "roles": [
        {
            "_id": "id_role_gdm_patient_same",
            "applicationId": "test_client_id",
            "applicationType": "client",
            "description": "GDM Patient",
            "name": "GDM Patient",
            "permissions": ["id_permission_write_goblin_same"],
        },
        {
            "_id": "id_role_system_same",
            "applicationId": "test_client_id",
            "applicationType": "client",
            "description": "System",
            "name": "System",
            "permissions": [
                "id_permission_write_elf_same",
                "id_permission_write_dwarf_same",
            ],
        },
        {
            "_id": "id_role_gdm_patient_different",
            "applicationId": "different_client_id",
            "applicationType": "client",
            "description": "GDM Patient",
            "name": "GDM Patient",
            "permissions": ["id_permission_write_goblin_different"],
        },
        {
            "_id": "id_role_system_different",
            "applicationId": "different_client_id",
            "applicationType": "client",
            "description": "System",
            "name": "System",
            "permissions": [
                "id_permission_write_elf_different",
                "id_permission_write_dwarf_different",
            ],
        },
    ]
}

SAMPLE_PERMISSIONS = {
    "permissions": [
        {
            "_id": "id_permission_write_goblin_same",
            "applicationId": "test_client_id",
            "applicationType": "client",
            "description": "write:goblin",
            "name": "write:goblin",
        },
        {
            "_id": "id_permission_write_elf_same",
            "applicationId": "test_client_id",
            "applicationType": "client",
            "description": "write:elf",
            "name": "write:elf",
        },
        {
            "_id": "id_permission_write_dwarf_same",
            "applicationId": "test_client_id",
            "applicationType": "client",
            "description": "write:dwarf",
            "name": "write:dwarf",
        },
        {
            "_id": "id_permission_write_goblin_different",
            "applicationId": "different_client_id",
            "applicationType": "client",
            "description": "write:goblin",
            "name": "write:goblin",
        },
        {
            "_id": "id_permission_write_elf_different",
            "applicationId": "different_client_id",
            "applicationType": "client",
            "description": "write:elf",
            "name": "write:elf",
        },
        {
            "_id": "id_permission_write_dwarf_different",
            "applicationId": "different_client_id",
            "applicationType": "client",
            "description": "write:dwarf",
            "name": "write:dwarf",
        },
    ]
}
