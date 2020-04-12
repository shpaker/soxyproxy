from dataclasses import dataclass

from soxyproxy.socks import ProtocolResponse
from soxyproxy.socks5.codes import AuthMethods
from soxyproxy.socks_versions import SocksVersions


@dataclass(frozen=True)
class HandshakeResponse(ProtocolResponse):
    auth_method: AuthMethods

    @property
    def as_bytes(self) -> bytes:
        return bytes([SocksVersions.SOCKS5.value, self.auth_method.value])
