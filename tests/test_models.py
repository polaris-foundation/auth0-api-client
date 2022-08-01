from typing import Dict

from auth0_api_client.models.group import Group
from auth0_api_client.models.permission import Permission
from auth0_api_client.models.role import Role


class TestModels:
    def test_group_to_dict(self) -> None:
        group = Group(
            group_id="id",
            description="desc",
            mappings=["mapping"],
            members=["member"],
            name="name",
            roles=["role"],
        )
        group_dict = group.to_dict()
        assert isinstance(group_dict, Dict)
        assert group_dict["description"] == "desc"

    def test_permission_to_dict(self) -> None:
        permission = Permission(
            permission_id="id",
            application_id="id",
            application_type="type",
            description="desc",
            name="name",
        )
        permission_dict = permission.to_dict()
        assert isinstance(permission_dict, Dict)
        assert permission_dict["description"] == "desc"

    def test_role_to_dict(self) -> None:
        role = Role(
            role_id="id",
            application_id="id",
            application_type="type",
            description="desc",
            name="name",
            permissions=["permission"],
        )
        role_dict = role.to_dict()
        assert isinstance(role_dict, Dict)
        assert role_dict["description"] == "desc"
