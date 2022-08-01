from typing import Dict, List

import requests
from she_logging import logger

from auth0_api_client import jwt as auth0_jwt
from auth0_api_client.authz import redact_jwt_signature
from auth0_api_client.config import auth0_config
from auth0_api_client.errors import Auth0ConnectionError, Auth0OperationError


def get_mgmt_jwt() -> str:
    """
    Gets a JWT that can be used to manage Auth0 infrastructure such as the client, connection and API. The credentials
    required must be specified in the environment variables AUTH0_AUTHZ_CLIENT_ID and AUTH0_AUTHZ_CLIENT_SECRET.
    :raises Auth0ConnectionError: If communication with Auth0 fails.
    :return: A valid JWT from Auth0
    """
    logger.info("Retrieving JWT for Auth0 mgmt client")
    return auth0_jwt.get_auth0_jwt_for_client(
        client_id=auth0_config["AUTH0_MGMT_CLIENT_ID"],
        client_secret=auth0_config["AUTH0_MGMT_CLIENT_SECRET"],
        audience=f"{auth0_config['NONCUSTOM_AUTH0_DOMAIN']}/api/v2/",
    )


def request_password_reset(email_address: str) -> str:
    """
    Requests a password reset for a user with the provided email address.
    :raises Auth0ConnectionError: If communication with Auth0 fails.
    :param email_address: The email address of the user to reset the password for
    :return: A url containing the password reset ticket url
    """
    logger.info(
        f"Requesting password reset for user with email address '{email_address}'"
    )
    mgmt_jwt: str = get_mgmt_jwt()
    payload = {
        "connection_id": _get_connection_id(_jwt=mgmt_jwt),
        "email": email_address,
        "result_url": auth0_config["PROXY_URL"],
    }
    try:
        pass_change_response = requests.post(
            f"{auth0_config['NONCUSTOM_AUTH0_DOMAIN']}/api/v2/tickets/password-change",
            headers={"Authorization": f"Bearer {mgmt_jwt}"},
            json=payload,
            timeout=10,
        )
        pass_change_response.raise_for_status()
    except requests.HTTPError as e:
        logger.exception(
            "Couldn't request password reset using Auth0 management API",
            extra={"access_token": redact_jwt_signature(mgmt_jwt)},
        )
        raise Auth0ConnectionError(e)

    ticket_url = pass_change_response.json()["ticket"]
    logger.info("Successfully reset password, ticket url: %s", ticket_url)
    return ticket_url


def _get_connection_id(_jwt: str) -> str:
    logger.debug("Getting connections from Auth0 mgmt API")
    connections: List[Dict] = []
    page = 0
    try:
        while True:
            # Endpoint is paginated, so iterate through pages until we get an empty response.
            connections_response = requests.get(
                f"{auth0_config['NONCUSTOM_AUTH0_DOMAIN']}/api/v2/connections",
                headers={"Authorization": f"Bearer {_jwt}"},
                params={"page": page, "per_page": 50},
                timeout=10,
            )
            connections_response.raise_for_status()
            paginated_connections: List[Dict] = connections_response.json()
            if not paginated_connections:
                break
            connections += paginated_connections
            page += 1
    except requests.HTTPError as e:
        logger.exception(
            "Couldn't get Auth0 connections from Auth0 management API",
            extra={"access_token": _jwt},
        )
        raise Auth0ConnectionError(e)

    base_domain = (auth0_config["PROXY_URL"].split("//")[1]).split(".")[0]
    connection_name = base_domain + "-users"
    connection = next((c for c in connections if c["name"] == connection_name), None)
    if connection is None:
        raise Auth0OperationError(
            f"Unable to find database connection '{connection_name}' in Auth0"
        )

    logger.info("Found DB connection '%s', id: '%s", connection_name, connection["id"])
    return connection["id"]
