from dataclasses import dataclass

from soxyproxy.consts import SOCKS5_USERNAME_AUTH_VERSION
from soxyproxy.models.socks5.common import RequestMessage

USERNAME_AUTH_VERSION_INDEX = 0
USERNAME_LEN_INDEX = 1
USERNAME_INDEX = 2


@dataclass
class Socks5UsernameAuthRequestMessage(RequestMessage):
    username: str
    password: str

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = raw[USERNAME_AUTH_VERSION_INDEX]
        except (ValueError, IndexError) as err:
            raise ValueError(f"incorrect authorization package: {raw}") from err

        if socks_version != SOCKS5_USERNAME_AUTH_VERSION:
            raise ValueError(f"incorrect authorization package: {raw}")

        username_len: int = raw[USERNAME_LEN_INDEX]
        username_slice = slice(USERNAME_INDEX, USERNAME_INDEX + username_len)
        username: bytes = raw[username_slice]

        password_len: int = raw[USERNAME_INDEX + username_len]
        password_slice = slice(
            USERNAME_INDEX + 1 + username_len,
            USERNAME_INDEX + 1 + username_len + password_len,
        )
        password: bytes = raw[password_slice]

        return Socks5UsernameAuthRequestMessage(
            username=username.decode(), password=password.decode()
        )
