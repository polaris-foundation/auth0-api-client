import json
from typing import Any, Generator

import pytest
from _pytest.logging import LogCaptureFixture
from she_logging.logging import CustomisedJSONFormatter


@pytest.fixture(autouse=True)
def check_no_secrets_logged(caplog: LogCaptureFixture) -> Generator[None, None, None]:
    yield
    records = caplog.get_records("call")
    for record in records:
        for k, v in vars(record).items():
            if isinstance(v, str):
                parsed = json.loads(CustomisedJSONFormatter().format(record))

                failure_message = (
                    "a secret was found in the logs \n"
                    + 'key: "'
                    + k
                    + '" value: "'
                    + v
                    + '" from json log:\n'
                    + json.dumps(parsed, indent=4, sort_keys=True)
                )
                assert "secret" not in v, failure_message
