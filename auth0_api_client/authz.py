from typing import Dict, List, Optional, Tuple

import requests
from she_logging import logger

from auth0_api_client import jwt as auth0_jwt
from auth0_api_client.config import auth0_config
from auth0_api_client.errors import Auth0ConnectionError, Auth0OperationError
from auth0_api_client.models.group import Group
from auth0_api_client.models.permission import Permission
from auth0_api_client.models.role import Role


def get_authz_jwt() -> str:
    """
    Gets a JWT that can be used to manage groups, roles and permissions in the Auth0 authz extension. The credentials
    required must be specified in the environment variables AUTH0_AUTHZ_CLIENT_ID and AUTH0_AUTHZ_CLIENT_SECRET.
    :raises Auth0ConnectionError: If communication with Auth0 fails.
    :return: A valid JWT from Auth0
    """
    logger.info("Retrieving JWT for Auth0 authz extension client")
    return auth0_jwt.get_auth0_jwt_for_client(
        client_id=auth0_config["AUTH0_AUTHZ_CLIENT_ID"],
        client_secret=auth0_config["AUTH0_AUTHZ_CLIENT_SECRET"],
        audience="urn:auth0-authz-api",
    )


def get_permissions_for_group(group_name: str) -> List[Permission]:
    """
    Returns a list of the permissions associated with a particular group in the Auth0 authz extension. This method
    matches on a group name, finds the roles associated with it, and returns the permissions associated with those
    roles. Note that permissions/roles are only considered if they have an application ID matching the environment
    variable AUTH0_CLIENT_ID.
    :raises Auth0ConnectionError: If communication with Auth0 fails.
    :return: A list of the permissions in the Auth0 authz extension associated with the provided group name.
    """
    specified_permissions: List[Permission] = []

    authz_jwt: str = get_authz_jwt()
    groups_all, roles_all, permissions_all = _get_auth0_auth_contents(authz_jwt)

    # Get the specified group.
    specified_group: Optional[Group] = next(
        (g for g in groups_all if g.name.lower() == group_name.lower()), None
    )

    if specified_group is None:
        logger.info("No groups found with name '%s'", group_name)
        return specified_permissions

    # Filter roles and permissions to those for the configured client ID.
    filtered_roles = [
        r for r in roles_all if r.application_id == auth0_config["AUTH0_CLIENT_ID"]
    ]
    filtered_permissions = [
        p
        for p in permissions_all
        if p.application_id == auth0_config["AUTH0_CLIENT_ID"]
    ]

    # Identify the roles that are in the specified group, and the permissions that those roles have.
    specified_roles = [r for r in filtered_roles if r.role_id in specified_group.roles]
    specified_permission_ids: List[str] = [
        p for role in specified_roles for p in role.permissions
    ]

    # Return a list of all the permissions.
    return [
        p for p in filtered_permissions if p.permission_id in specified_permission_ids
    ]


def add_user_to_authz_groups(user_id: str, group_names: List[str]) -> None:
    """
    Adds a user to groups in the Auth0 authorization extension.
    :param user_id: The ID of the user to add to groups
    :param group_names: The names of the groups to which to add the user
    :raises Auth0ConnectionError: If communication with Auth0 fails
    :return: None
    """
    logger.debug("Adding user (%s) to groups (%s)", user_id, group_names)

    authz_jwt: str = get_authz_jwt()
    group_ids = _retrieve_authz_groups_ids_by_name(group_names, authz_jwt)
    logger.debug("Found group IDs in authz", extra={"group_ids": group_ids})

    logger.debug("Patching user %s into group_ids: %s", user_id, group_ids)
    try:
        add_response = requests.patch(
            f"{auth0_config['AUTH0_AUTHZ_WEBTASK_URL']}/users/auth0%7C{user_id}/groups",
            headers={"Authorization": f"Bearer {get_authz_jwt()}"},
            json=group_ids,
            timeout=10,
        )
        add_response.raise_for_status()
    except requests.HTTPError as e:
        logger.exception("Couldn't add user to authz groups")
        raise Auth0ConnectionError(e)
    logger.debug(
        "Successfully patched user %s",
        user_id,
        extra={"status_code": add_response.status_code},
    )


def remove_user_from_authz_groups(user_id: str, group_names: List[str]) -> None:
    """
    Removes a user from groups in the Auth0 authorization extension.
    :param user_id: The ID of the user to remove from groups
    :param group_names: The names of the groups from which to remove the user
    :raises Auth0ConnectionError: If communication with Auth0 fails
    :return: None
    """
    logger.debug("Removing user (%s) from groups (%s)", user_id, group_names)

    authz_jwt: str = get_authz_jwt()
    group_ids = _retrieve_authz_groups_ids_by_name(group_names, authz_jwt)
    logger.debug("Found group IDs in authz", extra={"group_ids": group_ids})

    logger.debug("Deleting group_ids %s from user %s", group_ids, user_id)
    for group_uuid in group_ids:
        logger.debug("Deleting user %s out of group_ids %s", user_id, group_ids)
        try:
            remove_response = requests.delete(
                f"{auth0_config['AUTH0_AUTHZ_WEBTASK_URL']}/groups/{group_uuid}/members",
                headers={"Authorization": f"Bearer {authz_jwt}"},
                json=[f"auth0|{user_id}"],
                timeout=10,
            )
            remove_response.raise_for_status()
        except requests.HTTPError as e:
            logger.exception("Couldn't remove user from authz group")
            raise Auth0ConnectionError(e)
        logger.debug(
            "Successfully removed user %s from groups",
            user_id,
            extra={"status_code": remove_response.status_code},
        )


def _retrieve_authz_groups_ids_by_name(group_names: List[str], jwt: str) -> List[str]:
    logger.debug("Retrieving all groups from Authz extension")
    groups = _get_auth0_auth_groups(jwt)

    group_uuids: List[str] = [g.group_id for g in groups if g.name in group_names]

    if len(group_uuids) != len(group_names):
        not_found_groups = [n for n in group_names if n not in [g.name for g in groups]]

        logger.debug(
            "Requested group(s) did not exist in Auth0 authz: %s", not_found_groups
        )
        raise Auth0OperationError("Group not found")

    return group_uuids


def _get_auth0_auth_contents(
    _jwt: str,
) -> Tuple[List[Group], List[Role], List[Permission]]:
    url_base: str = auth0_config["AUTH0_AUTHZ_WEBTASK_URL"]
    headers: Dict = {"Authorization": f"Bearer {_jwt}"}
    permissions_response = requests.get(
        f"{url_base}/permissions", headers=headers, timeout=10
    )
    roles_response = requests.get(f"{url_base}/roles", headers=headers, timeout=10)
    groups_response = requests.get(f"{url_base}/groups", headers=headers, timeout=10)
    try:
        permissions_response.raise_for_status()
        roles_response.raise_for_status()
        groups_response.raise_for_status()
    except requests.HTTPError as e:
        logger.exception(
            "Couldn't retrieve content from Auth0 auth extension",
            extra={"access_token": redact_jwt_signature(_jwt)},
        )
        raise Auth0ConnectionError(e)
    groups_all: List[Group] = [
        Group.from_dict(g) for g in groups_response.json()["groups"]
    ]
    roles_all: List[Role] = [Role.from_dict(r) for r in roles_response.json()["roles"]]
    permissions_all: List[Permission] = [
        Permission.from_dict(p) for p in permissions_response.json()["permissions"]
    ]

    return groups_all, roles_all, permissions_all


def _get_auth0_auth_groups(_jwt: str) -> List[Group]:
    try:
        groups_response = requests.get(
            f"{auth0_config['AUTH0_AUTHZ_WEBTASK_URL']}/groups",
            headers={"Authorization": f"Bearer {_jwt}"},
            timeout=10,
        )
        groups_response.raise_for_status()
    except requests.HTTPError as e:
        logger.exception(
            "Couldn't retrieve groups from Auth0 auth extension",
            extra={"access_token": redact_jwt_signature(_jwt)},
        )
        raise Auth0ConnectionError(e)
    return [Group.from_dict(g) for g in groups_response.json()["groups"]]


def redact_jwt_signature(jwt: str) -> str:
    return jwt.rsplit(".", 1)[0]
