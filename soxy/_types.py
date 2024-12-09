import asyncio
import enum
import types
import typing
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

type Resolver = typing.Callable[[str], IPv4Address | typing.Awaitable[IPv4Address]]

type Socks4Auther = typing.Callable[[str], bool]
type Socks4AsyncAuther = typing.Callable[[str], typing.Awaitable[bool]]

type Socks5Auther = typing.Callable[[str, str], bool]
type Socks5AsyncAuther = typing.Callable[[str, str], typing.Awaitable[bool]]

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
    GRANTED = 0x5A
    REJECTED = 0x5B
    IDENTD_NOT_REACHABLE = 0x5C
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
    IPv4 = 1
    DOMAIN = 3
    IPv6 = 4


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
    typing.NamedTuple,
):
    ip: IPv4Address | IPv6Address
    port: int


class Connection(
    typing.Protocol,
):
    _address: Address

    def __repr__(
        self,
    ) -> str:
        return f'<soxy.{self.__class__.__name__} id={id(self)} {self.address.ip}:{self.address.port}>'

    @property
    def address(
        self,
    ) -> Address:
        return self._address

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
    ) -> typing.Self: ...
    async def read(
        self,
    ) -> bytes: ...
    async def write(
        self,
        data: bytes,
    ) -> None: ...


class Transport(
    typing.Protocol,
):
    def init(
        self,
        on_client_connected_cb: typing.Callable[
            [Connection],
            typing.Awaitable[Address | None],
        ],
        start_messaging_cb: typing.Callable[
            [Connection, Connection],
            typing.Awaitable[None],
        ],
        on_remote_unreachable_cb: typing.Callable[
            [Connection, Address],
            typing.Awaitable[None],
        ],
    ) -> None: ...

    def __repr__(
        self,
    ) -> str:
        return f'<soxy.{self.__class__.__name__}>'

    async def __aenter__(self) -> asyncio.Server: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: types.TracebackType | None,
    ) -> None: ...


class ProxySocks(
    typing.Protocol,
):
    def __repr__(
        self,
    ) -> str:
        return f'<soxy.{self.__class__.__name__}>'

    async def __call__(
        self,
        client: Connection,
    ) -> tuple[Address, str | None]: ...

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None: ...
    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None: ...
    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None: ...
