import os


def get_env_value(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"{name} needs to be set in the environment.")
    return value
