from dataclasses import dataclass

from soxyproxy.socks import ProtocolRequest
from soxyproxy.socks5.codes import USERNAME_AUTH_VERSION

USERNAME_AUTH_VERSION_INDEX = 0
USERNAME_LEN_INDEX = 1
USERNAME_INDEX = 2


@dataclass
class UsernameAuthRequest(ProtocolRequest):
    username: str
    password: str

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = raw[USERNAME_AUTH_VERSION_INDEX]
        except (ValueError, IndexError):
            raise ValueError(f'incorrect authorization package: {raw}')

        if socks_version != USERNAME_AUTH_VERSION:
            raise ValueError(f'incorrect authorization package: {raw}')

        username_len: int = raw[USERNAME_LEN_INDEX]
        username_slice = slice(USERNAME_INDEX, USERNAME_INDEX + username_len)
        username: bytes = raw[username_slice]

        password_len: int = raw[USERNAME_INDEX + username_len]
        password_slice = slice(USERNAME_INDEX + 1 + username_len, USERNAME_INDEX + 1 + username_len + password_len)
        password: bytes = raw[password_slice]

        return UsernameAuthRequest(username=username.decode(), password=password.decode())
