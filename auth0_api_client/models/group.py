from typing import Dict, List, Optional


class Group:
    def __init__(
        self,
        group_id: str,
        description: str,
        mappings: List[str],
        members: List[str],
        name: str,
        roles: List[str],
    ) -> None:
        self.group_id = group_id
        self.description = description
        self.mappings = mappings
        self.members = members
        self.name = name
        self.roles = roles

    def to_dict(self) -> Dict:
        return {
            "_id": self.group_id,
            "description": self.description,
            "mappings": self.mappings,
            "members": self.members,
            "name": self.name,
            "roles": self.roles,
        }

    @classmethod
    def from_dict(cls, group_dict: Dict) -> "Group":
        group: Group = Group(
            group_id=group_dict["_id"],
            description=group_dict["description"],
            mappings=group_dict.get("mappings", []),
            members=group_dict.get("members", []),
            name=group_dict["name"],
            roles=group_dict.get("roles", []),
        )
        return group
