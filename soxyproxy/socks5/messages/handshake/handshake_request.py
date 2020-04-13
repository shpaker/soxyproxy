from dataclasses import dataclass
from typing import List

from soxyproxy.socks import ProtocolRequest
from soxyproxy.socks5.codes import AuthMethods
from soxyproxy.socks_versions import SocksVersions

SOCKS_VERSION_INDEX = 0
AUTH_METHODS_COUNT_INDEX = 1
AUTH_METHOD_SLICE = slice(2, None)


@dataclass(frozen=True)
class HandshakeRequest(ProtocolRequest):

    auth_methods: List[AuthMethods]

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = SocksVersions(raw[SOCKS_VERSION_INDEX])
            if socks_version != SocksVersions.SOCKS5:
                raise ValueError
        except (ValueError, IndexError):
            raise ValueError(f'incorrect handshake package: {raw}')

        auth_methods_count: int = raw[AUTH_METHODS_COUNT_INDEX]
        auth_methods: List = [AuthMethods(id) for id in list(raw[AUTH_METHOD_SLICE])]

        if len(auth_methods) != auth_methods_count:
            raise ValueError(f'incorrect handshake package: {raw}')

        return HandshakeRequest(auth_methods=auth_methods)
