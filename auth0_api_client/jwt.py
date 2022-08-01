import json
from typing import Optional

import requests
from requests import Response
from she_logging import logger

from auth0_api_client import auth0_config
from auth0_api_client.errors import Auth0ConnectionError
from auth0_api_client.rate_limit_handler import prevent_or_handle_429


def get_auth0_jwt_for_client(client_id: str, client_secret: str, audience: str) -> str:
    """
    Gets an Auth0 JWT using an Auth0 client's credentials.
    """

    url = f"{auth0_config['NONCUSTOM_AUTH0_DOMAIN']}/oauth/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
        "grant_type": "client_credentials",
    }

    try:
        jwt_response: requests.Response = prevent_or_handle_429(
            method="post",
            url=url,
            json=payload,
            timeout=10,
        )
        jwt_response.raise_for_status()
        return jwt_response.json()["access_token"]
    except requests.HTTPError as e:
        logger.exception("Couldn't retrieve JWT for Auth0 client")
        error_response: Optional[Response] = e.response
        payload.pop("client_secret", None)
        logger.debug(
            "Request payload: %s",
            json.dumps(payload),
        )
        if error_response is not None:
            logger.debug(
                "Response (HTTP code %d): %s",
                error_response.status_code,
                error_response.text,
            )
        raise Auth0ConnectionError(e)


def get_auth0_jwt_for_user(username: str, password: str) -> str:
    """
    Gets an Auth0 JWT using an Auth0 user's credentials.
    """

    base_domain: str = (auth0_config["PROXY_URL"].split("//")[1]).split(".")[0]
    customer_code: str = auth0_config["CUSTOMER_CODE"].lower()
    audience: str = auth0_config["AUTH0_AUDIENCE"]
    client_id: str = auth0_config["AUTH0_CLIENT_ID"]
    realm: str = f"{base_domain}-users"
    grant_type: str = "http://auth0.com/oauth/grant-type/password-realm"

    url: str = auth0_config["TOKEN_URL"]
    payload: str = (
        f"username={username}&password={password}"
        f"&customer_code={customer_code}"
        f"&audience={audience}"
        f"&client_id={client_id}"
        f"&realm={realm}"
        f"&grant_type={grant_type}"
    )

    headers = {
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        jwt_response = prevent_or_handle_429(
            method="post",
            url=url,
            data=payload,
            headers=headers,
            timeout=10,
        )
        jwt_response.raise_for_status()
        return jwt_response.json()["access_token"]
    except requests.HTTPError as e:
        logger.exception("Couldn't retrieve JWT for Auth0 user")
        error_response: Optional[Response] = e.response
        cleaned_payload: str = payload.replace(
            f"&password={password}", "&password=REDACTED"
        )
        logger.debug("Request payload: %s", cleaned_payload)
        if error_response is not None:
            logger.debug(
                "Response (HTTP code %d): %s",
                error_response.status_code,
                error_response.text,
            )
        raise Auth0ConnectionError(e)
