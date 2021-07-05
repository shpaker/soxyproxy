from dataclasses import dataclass

from soxyproxy.consts import Socks5AuthReplies, SOCKS5_USERNAME_AUTH_VERSION
from soxyproxy.models.socks5.common import ResponseMessage


@dataclass(frozen=True)
class Socks5UsernameAuthResponseMessage(ResponseMessage):

    status: bool

    @property
    def as_bytes(self):
        auth_status: Socks5AuthReplies = (
            Socks5AuthReplies.SUCCESS if self.status else Socks5AuthReplies.FAIL
        )
        return bytes([SOCKS5_USERNAME_AUTH_VERSION, auth_status.value])
