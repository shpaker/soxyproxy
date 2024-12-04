from soxy._config import Config
from soxy._errors import (
    AuthorizationError,
    ConfigError,
    PackageError,
    ProtocolError,
    RejectError,
    ResolveDomainError,
)
from soxy._logger import logger
from soxy._proxy import Proxy
from soxy._ruleset import ConnectingRule, ProxyingRule, Ruleset
from soxy._socks import Socks4, Socks5
from soxy._tcp import TcpTransport
from soxy._types import (
    Address,
    Connection,
    Resolver,
)

__title__ = 'winregistry'
__version__ = '0.0.0'
__url__ = 'https://github.com/shpaker/soxyproxy'
__author__ = 'Aleksandr Shpak'
__author_email__ = 'shpaker@gmail.com'
__license__ = 'MIT'
__all__ = [
    'Address',
    'AuthorizationError',
    'Config',
    'ConfigError',
    'ConnectingRule',
    'Connection',
    'PackageError',
    'ProtocolError',
    'Proxy',
    'ProxyingRule',
    'RejectError',
    'ResolveDomainError',
    'Resolver',
    'Ruleset',
    'Socks4',
    'Socks5',
    'TcpTransport',
    'logger',
]
