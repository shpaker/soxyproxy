import struct
import typing
from abc import ABC, abstractmethod
from ipaddress import IPV4LENGTH, IPV6LENGTH, AddressValueError, IPv4Address, IPv6Address

from soxy._errors import PackageError
from soxy._types import (
    Address,
    Connection,
    Socks4Command,
    Socks4Reply,
    Socks5AddressType,
    Socks5AuthMethod,
    Socks5AuthReply,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersions,
)
from soxy._utils import port_from_bytes, port_to_bytes


class _BaseRequestPackage(
    ABC,
):
    def __init__(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        if not data:
            raise PackageError(data)
        self._client = client
        self._data = data
        if not self._validate():
            raise PackageError(data)

    @property
    def data(
        self,
    ) -> bytes:
        return self._data

    @property
    def client(
        self,
    ) -> Connection:
        return self._client

    @abstractmethod
    def _validate(
        self,
    ) -> bool:
        raise NotImplementedError

    @classmethod
    async def from_client(
        cls,
        client: Connection,
    ) -> typing.Self:
        data = await client.read()
        return cls(
            client=client,
            data=data,
        )


class _BaseResponsePackage(
    ABC,
):
    def __init__(
        self,
        client: Connection,
    ) -> None:
        self._client = client

    @property
    @abstractmethod
    def data(
        self,
    ) -> bytes:
        raise NotImplementedError

    async def to_client(
        self,
    ) -> None:
        return await self._client.write(self.data)


class Socks4Request(
    _BaseRequestPackage,
):
    def __init__(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        self._destination: Address | None = None
        self._is_socks4a: bool | None = None
        self._username: str | None = None
        self._domain_name: str | None = None
        super().__init__(
            client=client,
            data=data,
        )

    def _validate(
        self,
    ) -> bool:
        return not any(
            [
                self.socks_version is not SocksVersions.SOCKS4,
                self._data[-1] != 0,
                self.is_socks4a and not self.domain_name,
            ]
        )

    @property
    def socks_version(
        self,
    ) -> SocksVersions:
        try:
            socks_version = SocksVersions(self._data[0])
        except ValueError as exc:
            raise PackageError(self.data) from exc
        return socks_version

    @property
    def command(
        self,
    ) -> Socks4Command:
        try:
            command = Socks4Command(self._data[1])
        except ValueError as exc:
            raise PackageError(self.data) from exc
        return command

    @property
    def destination(
        self,
    ) -> Address:
        if self._destination:
            return self._destination
        try:
            port, raw_address = struct.unpack('!HI', self._data[2:8])
        except (struct.error, IndexError) as exc:
            raise PackageError(self.data) from exc
        self._destination = Address(
            ip=IPv4Address(raw_address),
            port=port,
        )
        return self._destination

    @property
    def is_socks4a(
        self,
    ) -> bool:
        if self._is_socks4a:
            return self._is_socks4a
        self._is_socks4a = isinstance(self.destination.ip, IPv4Address) and self.destination.ip <= IPv4Address(0xFF)
        return self._is_socks4a

    @property
    def username(
        self,
    ) -> str | None:
        if not self._username:
            self._extract_data_from_tail()
        return self._username

    @property
    def domain_name(
        self,
    ) -> str | None:
        if not self._domain_name:
            self._extract_data_from_tail()
        return self._domain_name

    def _extract_data_from_tail(
        self,
    ) -> None:
        tail = self._data[8:-1]
        username_bytes: bytes | None
        domain_bytes: bytes | None
        if b'\x00' in tail:
            try:
                username_bytes, domain_bytes = tail.split(b'\x00')
            except (ValueError, IndexError) as exc:
                raise PackageError(tail) from exc
        else:
            username_bytes, domain_bytes = (tail, None) if not self.is_socks4a else (None, tail)
        if not self.is_socks4a and domain_bytes:
            raise PackageError(self.data)
        try:
            self._username = username_bytes.decode() if username_bytes else None
            self._domain_name = domain_bytes.decode() if domain_bytes else None
        except UnicodeError as exc:
            raise PackageError(self.data) from exc


class Socks4Response(
    _BaseResponsePackage,
):
    def __init__(
        self,
        client: Connection,
        reply: Socks4Reply,
        destination: Address | None = None,
    ) -> None:
        if destination is None:
            destination = Address(ip=IPv4Address(1), port=0)
        super().__init__(client)
        self._reply = reply
        self._destination = destination
        self._data = bytes([0, reply.value]) + port_to_bytes(destination.port) + destination.ip.packed

    @property
    def destination(
        self,
    ) -> Address:
        return self._destination

    @property
    def data(
        self,
    ) -> bytes:
        return self._data


class Socks5GreetingRequest(
    _BaseRequestPackage,
):
    def __init__(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        self._methods: list[Socks5AuthMethod] | None = None
        self._methods_num: int | None = None
        super().__init__(
            client=client,
            data=data,
        )

    def _validate(
        self,
    ) -> bool:
        return not any(
            [
                self.socks_version is not SocksVersions.SOCKS5,
                self.methods_num != len(self.methods),
            ]
        )

    @property
    def socks_version(
        self,
    ) -> SocksVersions:
        try:
            socks_version = SocksVersions(self._data[0])
        except ValueError as exc:
            raise PackageError(self.data) from exc
        return socks_version

    @property
    def methods_num(
        self,
    ) -> int:
        if self._methods_num:
            return self._methods_num
        try:
            self._methods_num = self._data[1]
        except IndexError as exc:
            raise PackageError(self.data) from exc
        return self._methods_num

    @property
    def methods(
        self,
    ) -> list[Socks5AuthMethod]:
        if self._methods:
            return self._methods
        try:
            self._methods = [Socks5AuthMethod(raw_method) for raw_method in list(self._data[2:])]
        except (IndexError, ValueError) as exc:
            raise PackageError(self.data) from exc
        return self._methods


class Socks5GreetingResponse(
    _BaseResponsePackage,
):
    def __init__(
        self,
        method: Socks5AuthMethod,
        client: Connection,
    ) -> None:
        self._method = method
        super().__init__(client)

    @property
    def data(
        self,
    ) -> bytes:
        return bytes([SocksVersions.SOCKS5.value, self._method.value])

    @property
    def method(
        self,
    ) -> Socks5AuthMethod:
        return self._method


class Socks5AuthorizationRequest(
    _BaseRequestPackage,
):
    def __init__(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        self._username: str | None = None
        self._password: str | None = None
        try:
            self._username_length = data[1]
            self._password_length = data[2 + self._username_length]
        except IndexError as exc:
            raise PackageError(data) from exc
        super().__init__(
            client=client,
            data=data,
        )

    def _validate(
        self,
    ) -> bool:
        return all(
            [
                self._data[0] == 1,
                self._username_length == len(self.username),
                self._password_length == len(self.password),
            ]
        )

    @property
    def username(
        self,
    ) -> str:
        if self._username:
            return self._username
        try:
            self._username = self._data[2 : 2 + self._username_length].decode()
        except (IndexError, UnicodeError) as exc:
            raise PackageError(self._data) from exc
        return self._username

    @property
    def password(
        self,
    ) -> str:
        if self._password:
            return self._password
        try:
            self._password = self._data[
                3 + self._username_length : 3 + self._username_length + self._password_length
            ].decode()
        except (IndexError, UnicodeError) as exc:
            raise PackageError(self._data) from exc
        return self._password


class Socks5AuthorizationResponse(
    _BaseResponsePackage,
):
    def __init__(
        self,
        is_success: bool,
        client: Connection,
    ) -> None:
        self._is_success = is_success
        super().__init__(client)

    @property
    def is_success(
        self,
    ) -> bool:
        return self._is_success

    @property
    def data(
        self,
    ) -> bytes:
        reply = Socks5AuthReply.SUCCESS if self._is_success is True else Socks5AuthReply.FAIL
        return bytes([1, reply.value])


class Socks5ConnectionRequest(
    _BaseRequestPackage,
):
    def __init__(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        self._command: Socks5Command | None = None
        self._address_type: Socks5AddressType | None = None
        self._destination: Address | None = None
        self._domain_name: str | None = None
        self._port: int | None = None
        super().__init__(
            client=client,
            data=data,
        )

    def _validate(
        self,
    ) -> bool:
        return not any(
            [
                self.socks_version is not SocksVersions.SOCKS5,
                self.command is not Socks5Command.CONNECT,
            ],
        )

    @property
    def socks_version(
        self,
    ) -> SocksVersions:
        try:
            socks_version = SocksVersions(self._data[0])
        except ValueError as exc:
            raise PackageError(self.data) from exc
        return socks_version

    @property
    def command(
        self,
    ) -> Socks5Command:
        if self._command:
            return self._command
        try:
            self._command = Socks5Command(self.data[1])
        except ValueError as exc:
            raise PackageError(self.data) from exc
        return self._command

    @property
    def address_type(
        self,
    ) -> Socks5AddressType:
        if self._address_type:
            return self._address_type
        try:
            self._address_type = Socks5AddressType(self._data[3])
        except (ValueError, IndexError) as exc:
            raise PackageError(data=self.data) from exc
        return self._address_type

    @property
    def is_socks5h(
        self,
    ) -> bool:
        return self.address_type is Socks5AddressType.DOMAIN

    @property
    def port(
        self,
    ) -> int:
        if self._port:
            return self._port
        try:
            self._port = port_from_bytes(self._data[-2:])
        except (ValueError, IndexError) as exc:
            raise PackageError(data=self.data) from exc
        return self._port

    @property
    def domain_name(
        self,
    ) -> str | None:
        if self._domain_name or self.address_type is not Socks5AddressType.DOMAIN:
            return self._domain_name
        if self.address_type is Socks5AddressType.DOMAIN:
            try:
                domain_name_len = self._data[4]
                self._domain_name = self._data[5 : 5 + domain_name_len].decode()
            except (IndexError, UnicodeError) as exc:
                raise PackageError(data=self.data) from exc
        return self._domain_name

    @property
    def destination(
        self,
    ) -> Address | None:
        if self._destination is not None or self.address_type is Socks5AddressType.DOMAIN:
            return self._destination
        try:
            port = port_from_bytes(self._data[-2:])
        except IndexError as exc:
            raise PackageError(self._data) from exc
        match self.address_type:
            case Socks5AddressType.IPv4:
                try:
                    self._destination = Address(
                        ip=IPv4Address(self._data[4 : 4 + IPV4LENGTH // 8]),
                        port=port,
                    )
                except (IndexError, AddressValueError) as exc:
                    raise PackageError(self._data) from exc
            case Socks5AddressType.IPv6:
                try:
                    self._destination = Address(
                        ip=IPv6Address(self._data[4 : 4 + IPV6LENGTH // 8]),
                        port=port,
                    )
                except (IndexError, AddressValueError) as exc:
                    raise PackageError(self._data) from exc
        return self._destination


class Socks5ConnectionResponse(
    _BaseResponsePackage,
):
    def __init__(
        self,
        client: Connection,
        reply: Socks5ConnectionReply,
        destination: str | IPv4Address | IPv6Address | None = None,
        port: int = 0,
    ) -> None:
        if destination is None:
            destination = IPv4Address(0)
        self._reply = reply
        self._destination = destination
        self._port = port
        super().__init__(client)

    @property
    def data(
        self,
    ) -> bytes:
        response = bytes([SocksVersions.SOCKS5.value, self._reply.value, 0])
        if isinstance(self._destination, IPv4Address):
            response += bytes([Socks5AddressType.IPv4.value]) + self._destination.packed
        if isinstance(self._destination, IPv6Address):
            response += bytes([Socks5AddressType.IPv6.value]) + self._destination.packed
        if isinstance(self._destination, str):
            address_types = Socks5AddressType.DOMAIN
            response += bytes([address_types.value, len(self._destination)]) + self._destination.encode()
        return response + port_to_bytes(self._port)
