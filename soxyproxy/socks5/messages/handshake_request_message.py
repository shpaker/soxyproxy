from dataclasses import dataclass
from typing import List

from soxyproxy.protocols import Protocols
from soxyproxy.socks import RequestMessage
from soxyproxy.socks5 import Socks5AuthMethods

SOCKS_VERSION_INDEX = 0
AUTH_METHODS_COUNT_INDEX = 1
AUTH_METHOD_SLICE = slice(2, None)


@dataclass(frozen=True)
class Socks5HandshakeRequestMessage(RequestMessage):

    auth_methods: List[Socks5AuthMethods]

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = Protocols(raw[SOCKS_VERSION_INDEX])
            if socks_version != Protocols.SOCKS5:
                raise ValueError
        except (ValueError, IndexError):
            raise ValueError(f'incorrect handshake package: {raw}')

        auth_methods_count: int = raw[AUTH_METHODS_COUNT_INDEX]
        auth_methods: List = [Socks5AuthMethods(id) for id in list(raw[AUTH_METHOD_SLICE])]

        if len(auth_methods) != auth_methods_count:
            raise ValueError(f'incorrect handshake package: {raw}')

        return Socks5HandshakeRequestMessage(auth_methods=auth_methods)
