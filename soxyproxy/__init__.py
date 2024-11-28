from soxyproxy._errors import (
    ProtocolError,
    PackageError,
    RejectError,
    ResolveDomainError,
    AuthorizationError,
)
from soxyproxy._service import ProxyService
from soxyproxy._socks4 import Socks4
from soxyproxy._socks5 import Socks5
from soxyproxy._tcp import TcpServer
from soxyproxy._types import (
    Connection,
    Destination,
    ProxySocks,
    ProxyTransport,
)

__all__ = [
    "Connection",
    "Destination",
    "ProxyService",
    # types
    "ProxySocks",
    "ProxyTransport",
    # protocol implementations
    "Socks4",
    "Socks5",
    # errors
    "ProtocolError",
    "ResolveDomainError",
    "PackageError",
    "RejectError",
    "AuthorizationError",
    # transports
    "TcpServer",
]
