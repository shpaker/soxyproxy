from dataclasses import dataclass

from soxyproxy.protocols import Protocols
from soxyproxy.socks import ResponseMessage
from soxyproxy.socks5 import Socks5AuthMethods


@dataclass(frozen=True)
class Socks5HandshakeResponseMessage(ResponseMessage):
    auth_method: Socks5AuthMethods

    @property
    def as_bytes(self) -> bytes:
        return bytes([Protocols.SOCKS5.value, self.auth_method.value])
