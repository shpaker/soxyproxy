from dataclasses import dataclass

from soxyproxy.socks import ProtocolResponse
from soxyproxy.socks5.codes import AuthStatus, USERNAME_AUTH_VERSION


@dataclass(frozen=True)
class UsernameAuthResponse(ProtocolResponse):

    status: bool

    @property
    def as_bytes(self):
        auth_status: AuthStatus = AuthStatus.SUCCESS if self.status else AuthStatus.FAIL
        return bytes([USERNAME_AUTH_VERSION, auth_status.value])
