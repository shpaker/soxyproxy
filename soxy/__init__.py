from soxy._config import Config
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
    Resolver,
)

__title__ = "winregistry"
__version__ = "0.0.0"
__url__ = "https://github.com/shpaker/soxyproxy"
__author__ = "Aleksandr Shpak"
__author_email__ = "shpaker@gmail.com"
__license__ = "MIT"
__all__ = [
    "Address",
    "AuthorizationError",
    "Config",
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
    "Resolver",
]
