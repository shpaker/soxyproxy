from typing import Any, Dict, List

from pydantic import Field, validator

from soxyproxy.consts import Socks5AuthMethod, SocksVersion
from soxyproxy.models.base import RequestBaseModel, ResponseBaseModel

SOCKS_VERSION_INDEX = 0
AUTH_METHODS_COUNT_INDEX = 1
AUTH_METHOD_SLICE = slice(2, None)


def extract_socks_version(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_auth_methods_count(raw: bytes) -> int:
    return raw[AUTH_METHODS_COUNT_INDEX]


def extract_auth_methods(raw: bytes) -> List[Socks5AuthMethod]:
    return [Socks5AuthMethod(raw_method) for raw_method in list(raw[AUTH_METHOD_SLICE])]


class RequestModel(RequestBaseModel["RequestModel"]):
    socks_version: SocksVersion
    auth_methods_count: int
    auth_methods: List[Socks5AuthMethod] = Field(min_items=1)

    @validator("socks_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ) -> int:
        if value != SocksVersion.SOCKS5:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @validator("auth_methods")
    def auth_methods_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,  # pylint: disable=unused-argument
        value: List[Socks5AuthMethod],
        values: Dict[str, Any],
        **kwargs: Any,  # noqa
    ) -> List[Socks5AuthMethod]:
        auth_methods_count = values["auth_methods_count"]
        if len(value) != auth_methods_count:
            raise ValueError("incorrect handshake package")
        return value

    @classmethod
    def loader(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        return cls(
            socks_version=extract_socks_version(raw),
            auth_methods_count=extract_auth_methods_count(raw),
            auth_methods=extract_auth_methods(raw),
        )


class ResponseModel(ResponseBaseModel):
    socks_version: SocksVersion = SocksVersion.SOCKS5
    auth_method: Socks5AuthMethod

    def dump(self) -> bytes:
        return bytes([self.socks_version.value, self.auth_method.value])
