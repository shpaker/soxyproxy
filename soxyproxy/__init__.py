from soxyproxy._errors import (
    AuthorizationError,
    PackageError,
    ProtocolError,
    RejectError,
    ResolveDomainError,
)
from soxyproxy._ruleset import Rule, Ruleset
from soxyproxy._service import ProxyService
from soxyproxy._socks4 import Socks4
from soxyproxy._socks5 import Socks5
from soxyproxy._tcp import TcpTransport
from soxyproxy._types import (
    Connection,
    Address,
    ProxySocks,
    ProxyTransport,
)

__all__ = [
    "AuthorizationError",
    "Connection",
    "Address",
    "PackageError",
    # errors
    "ProtocolError",
    "ProxyService",
    # types
    "ProxySocks",
    "ProxyTransport",
    "RejectError",
    "ResolveDomainError",
    "Rule",
    "Ruleset",
    # protocol implementations
    "Socks4",
    "Socks5",
    # transports
    "TcpTransport",
]
