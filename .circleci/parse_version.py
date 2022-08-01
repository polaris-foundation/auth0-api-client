import toml
from typing import Dict

config: Dict = toml.load("pyproject.toml")
print(config["tool"]["poetry"]["version"])
