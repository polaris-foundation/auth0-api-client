# Initialise config for this package.
from typing import Dict

from environs import Env

env = Env()
auth0_config_without_secrets: Dict[str, str] = {
    "PROXY_URL": env.str("PROXY_URL"),
    "CUSTOMER_CODE": env.str("CUSTOMER_CODE"),
    "TOKEN_URL": env.str("TOKEN_URL"),
    "AUTH0_MGMT_CLIENT_ID": env.str("AUTH0_MGMT_CLIENT_ID"),
    "AUTH0_AUTHZ_CLIENT_ID": env.str("AUTH0_AUTHZ_CLIENT_ID"),
    "AUTH0_AUTHZ_WEBTASK_URL": env.str("AUTH0_AUTHZ_WEBTASK_URL"),
    "AUTH0_CLIENT_ID": env.str("AUTH0_CLIENT_ID"),
    "AUTH0_AUDIENCE": env.str("AUTH0_AUDIENCE"),
    "NONCUSTOM_AUTH0_DOMAIN": env.str("NONCUSTOM_AUTH0_DOMAIN"),
}
auth0_config: Dict[str, str] = {
    **auth0_config_without_secrets,
    "AUTH0_MGMT_CLIENT_SECRET": env.str("AUTH0_MGMT_CLIENT_SECRET"),
    "AUTH0_AUTHZ_CLIENT_SECRET": env.str("AUTH0_AUTHZ_CLIENT_SECRET"),
}
