from typing import Dict, List, Optional


class Role:
    def __init__(
        self,
        role_id: str,
        application_id: str,
        application_type: str,
        description: str,
        name: str,
        permissions: List[str],
    ) -> None:
        self.role_id = role_id
        self.application_id = application_id
        self.application_type = application_type
        self.description = description
        self.name = name
        self.permissions = permissions

    def to_dict(self) -> Dict:
        return {
            "_id": self.role_id,
            "applicationId": self.application_id,
            "applicationType": self.application_type,
            "description": self.description,
            "name": self.name,
            "permissions": self.permissions,
        }

    @classmethod
    def from_dict(cls, role_dict: Dict) -> "Role":
        role = Role(
            role_id=role_dict["_id"],
            application_id=role_dict["applicationId"],
            application_type=role_dict["applicationType"],
            description=role_dict["description"],
            name=role_dict["name"],
            permissions=role_dict.get("permissions", []),
        )
        return role
