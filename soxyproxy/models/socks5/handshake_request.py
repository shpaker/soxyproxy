from typing import List, Dict, Any

from pydantic import Field, validator

from soxyproxy.consts import SocksVersion
from soxyproxy.models.base import RequestBaseModel
from soxyproxy.socks5 import Socks5AuthMethod

SOCKS_VERSION_INDEX = 0
AUTH_METHODS_COUNT_INDEX = 1
AUTH_METHOD_SLICE = slice(2, None)


def extract_socks_version(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_auth_methods_count(raw: bytes) -> int:
    return raw[AUTH_METHODS_COUNT_INDEX]


def extract_auth_methods(raw: bytes) -> List[Socks5AuthMethod]:
    return [Socks5AuthMethod(raw_method) for raw_method in list(raw[AUTH_METHOD_SLICE])]


def message_loads(raw: bytes) -> Dict[str, Any]:
    # check_raw_length(raw)
    return dict(
        socks_version=extract_socks_version(raw),
        auth_methods_count=extract_auth_methods_count(raw),
        auth_methods=extract_auth_methods(raw),
    )


class RequestModel(RequestBaseModel):
    socks_version: SocksVersion
    auth_methods_count: int
    auth_methods: List[Socks5AuthMethod] = Field(min_items=1)

    @validator("socks_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ):
        if value != SocksVersion.SOCKS5:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @validator("auth_methods")
    def auth_methods_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,  # pylint: disable=unused-argument
        value: List[Socks5AuthMethod],
        values: Dict[str, Any],
        **kwargs,
    ):
        auth_methods_count = values["auth_methods_count"]
        if len(value) != auth_methods_count:
            raise ValueError("incorrect handshake package")
        return value

    @classmethod
    def loads(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        data = message_loads(raw)
        return cls(**data)
