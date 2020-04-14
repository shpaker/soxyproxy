from dataclasses import dataclass

from soxyproxy.socks import ResponseMessage
from soxyproxy.socks5 import Socks5AuthReplies
from soxyproxy.socks5.messages.const import SOCKS5_USERNAME_AUTH_VERSION


@dataclass(frozen=True)
class Socks5UsernameAuthResponseMessage(ResponseMessage):

    status: bool

    @property
    def as_bytes(self):
        auth_status: Socks5AuthReplies = Socks5AuthReplies.SUCCESS if self.status else Socks5AuthReplies.FAIL
        return bytes([SOCKS5_USERNAME_AUTH_VERSION, auth_status.value])
