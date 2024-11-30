import enum
import typing as tp
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

type Resolver = tp.Callable[[str], IPv4Address | tp.Awaitable[IPv4Address]]
type Socks4Auther = tp.Callable[[str], None | tp.Awaitable[None]]
type Socks5Auther = tp.Callable[[str, str], None | tp.Awaitable[None]]
type IPvAnyAddress = IPv4Address | IPv6Address
type IPvAnyNetwork = IPv4Network | IPv6Network


class SocksVersions(
    enum.IntEnum,
):
    SOCKS4 = 4
    SOCKS5 = 5


class Socks4Command(
    enum.IntEnum,
):
    CONNECT = 1
    BIND = 2


class Socks4Reply(
    enum.IntEnum,
):
    GRANTED = 0x5A  # Request granted
    REJECTED = 0x5B  # Request rejected or failed
    # Failed because client is not running identd (or not reachable from server)
    IDENTD_NOT_REACHABLE = 0x5C
    # Failed because client's identd could not confirm the user ID in the request
    IDENTD_REJECTED = 0x5D


class Socks5AuthMethod(
    enum.IntEnum,
):
    NO_AUTHENTICATION = 0
    GSSAPI = 1
    USERNAME = 2
    NO_ACCEPTABLE = 255


class Socks5AuthReply(
    enum.IntEnum,
):
    SUCCESS = 0
    FAIL = 1


class Socks5Command(
    enum.IntEnum,
):
    CONNECT = 1
    BIND = 2
    UDP = 3


class Socks5AddressType(
    enum.IntEnum,
):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


class Socks5ConnectionReply(
    enum.IntEnum,
):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8


class Address(
    tp.NamedTuple,
):
    address: IPv4Address | IPv6Address
    port: int


class Connection(
    tp.Protocol,
):
    @property
    def address(self) -> Address: ...
    @classmethod
    async def open(cls, host: str, port: int) -> tp.Self: ...
    async def read(self) -> bytes: ...
    async def write(self, data: bytes) -> None: ...


class ProxyTransport(tp.Protocol):
    async def run(self, host: str, port: int) -> None: ...


class ProxySocks(
    tp.Protocol,
):
    async def __call__(self, client: Connection, data: bytes) -> Address: ...

    async def ruleset_reject(self, client: Connection, destination: Address): ...
    async def success(self, client: Connection, destination: Address) -> None: ...
    async def target_unreachable(
        self, client: Connection, destination: Address
    ) -> None: ...
