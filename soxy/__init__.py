from soxy._errors import (
    AuthorizationError,
    PackageError,
    ProtocolError,
    RejectError,
    ResolveDomainError,
)
from soxy._proxy import Proxy
from soxy._ruleset import Rule, Ruleset
from soxy._socks4 import Socks4
from soxy._socks5 import Socks5
from soxy._tcp import TcpTransport
from soxy._types import (
    Address,
    Connection,
)

__all__ = [
    "Address",
    "AuthorizationError",
    "Connection",
    "PackageError",
    "ProtocolError",
    "Proxy",
    "RejectError",
    "ResolveDomainError",
    "Rule",
    "Ruleset",
    "Socks4",
    "Socks5",
    "TcpTransport",
]
