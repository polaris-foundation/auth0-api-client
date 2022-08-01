from typing import Dict

from she_logging import logger

from auth0_api_client.config import auth0_config, auth0_config_without_secrets

# Initialise env vars early so that we complain as soon as possible if one is missing.
logger.debug(
    "Loaded Auth0 config via env vars", extra={"config": auth0_config_without_secrets}
)
logger.info("Auth0 API client initialised successfully!")
