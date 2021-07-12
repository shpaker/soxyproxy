from pydantic import validator

from soxyproxy.consts import Socks5AuthReply
from soxyproxy.models.base import RequestBaseModel, ResponseBaseModel

USERNAME_AUTH_VERSION_INDEX = 0
USERNAME_LEN_INDEX = 1
USERNAME_INDEX = 2
SOCKS5_USERNAME_AUTH_VERSION = 1


def extract_username_auth_version(raw: bytes) -> int:
    return raw[USERNAME_AUTH_VERSION_INDEX]


def extract_username_length(raw: bytes) -> int:
    return raw[USERNAME_LEN_INDEX]


def extract_username(raw: bytes) -> str:
    username_len: int = extract_username_length(raw)
    username_slice = slice(USERNAME_INDEX, USERNAME_INDEX + username_len)
    username: bytes = raw[username_slice]
    return username.decode()


def extract_password(raw: bytes) -> str:
    username_len: int = extract_username_length(raw)
    password_len: int = raw[USERNAME_INDEX + username_len]
    password_slice = slice(
        USERNAME_INDEX + 1 + username_len,
        USERNAME_INDEX + 1 + username_len + password_len,
    )
    password: bytes = raw[password_slice]
    return password.decode()


class RequestModel(RequestBaseModel["RequestModel"]):
    username_auth_version: int
    username: str
    password: str

    @validator("username_auth_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ) -> int:
        if value != SOCKS5_USERNAME_AUTH_VERSION:
            raise ValueError(f"incorrect authorization package: {value}")
        return value

    @classmethod
    def loader(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        return cls(
            username_auth_version=extract_username_auth_version(raw),
            username=extract_username(raw),
            password=extract_password(raw),
        )


class ResponseModel(ResponseBaseModel):
    status: bool

    def dump(self) -> bytes:
        auth_status: Socks5AuthReply = Socks5AuthReply.SUCCESS if self.status else Socks5AuthReply.FAIL
        return bytes([SOCKS5_USERNAME_AUTH_VERSION, auth_status.value])
