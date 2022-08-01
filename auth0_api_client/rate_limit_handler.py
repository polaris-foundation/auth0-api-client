import datetime
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union

import requests
from she_logging import logger


def retry_if_too_many_requests(
    max_attempts: int = 5,
    backoff_factor: int = 1,
) -> Callable:
    def wrapper(request_func: Callable) -> Callable:
        @wraps(request_func)
        def wrapped(*args: List, **kwargs: Dict) -> requests.Response:
            for attempt in range(max_attempts):
                logger.debug("Auth0 attempt %d", attempt + 1)

                response = request_func(*args, **kwargs)

                if response.status_code != 429:
                    return response

                response_json = response.json()
                reset_ts: Union[str, int, None] = response.headers.get(
                    "X-RateLimit-Reset"
                )
                remaining: Union[str, int, None] = response.headers.get(
                    "X-RateLimit-Remaining"
                )

                logger.warning(
                    "Auth0 Too Many Requests (429) response received.",
                    extra={
                        "json": response_json,
                        "X-RateLimit-Reset": reset_ts,
                        "X-RateLimit-Remaining": remaining,
                    },
                )
                if remaining is not None and reset_ts is not None:
                    remaining = int(remaining)

                    if not remaining:
                        if backoff_factor:
                            wait = backoff_factor * (
                                2 ** (max_attempts - (max_attempts - attempt))
                            )
                        else:
                            wait = max(
                                (
                                    datetime.datetime.fromtimestamp(int(reset_ts))
                                    - datetime.datetime.now()
                                ).seconds,
                                1,
                            )
                        logger.warning(
                            "Auth0 X-RateLimit-Limit exceeded. Retrying in %d seconds...",
                            wait,
                        )
                        time.sleep(wait)

            logger.error("Max. number of Auth0 attempts exceeded.")
            return response  # noqa

        return wrapped

    max_attempts = max(max_attempts, 1)

    return wrapper


def prevent_or_handle_429(
    method: str,
    url: str,
    params: Optional[Dict] = None,
    json: Optional[Dict] = None,
    data: Optional[Any] = None,
    headers: Optional[Dict] = None,
    timeout: int = 10,
) -> requests.Response:
    retrier: Callable = retry_if_too_many_requests()
    return retrier(getattr(requests, method))(
        url, params=params, json=json, data=data, headers=headers, timeout=timeout
    )
