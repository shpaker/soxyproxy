from soxyproxy.consts import SocksVersion, Socks5AuthMethod
from soxyproxy.models.base import ResponseBaseModel


class ResponseModel(ResponseBaseModel):
    socks_version: SocksVersion = SocksVersion.SOCKS5
    auth_method: Socks5AuthMethod

    def dumps(self) -> bytes:
        return bytes([self.socks_version.value, self.auth_method.value])
