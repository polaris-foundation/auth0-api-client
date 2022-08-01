from typing import Dict, Optional


class Permission:
    def __init__(
        self,
        permission_id: str,
        application_id: str,
        application_type: str,
        description: str,
        name: str,
    ) -> None:
        self.permission_id = permission_id
        self.application_id = application_id
        self.application_type = application_type
        self.description = description
        self.name = name

    def to_dict(self) -> Dict:
        return {
            "_id": self.permission_id,
            "applicationId": self.permission_id,
            "applicationType": self.application_type,
            "description": self.description,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, permission_dict: Dict) -> "Permission":
        permission = Permission(
            permission_id=permission_dict["_id"],
            application_id=permission_dict["applicationId"],
            application_type=permission_dict["applicationType"],
            description=permission_dict["description"],
            name=permission_dict["name"],
        )
        return permission
