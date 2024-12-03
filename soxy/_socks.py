import struct
import typing
from abc import ABC, abstractmethod
from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address

from soxy._errors import (
    PackageError,
    RejectError,
    ResolveDomainError,
)
from soxy._logger import logger
from soxy._types import (
    Address,
    Connection,
    Resolver,
    Socks4AsyncAuther,
    Socks4Auther,
    Socks4Command,
    Socks4Reply,
    Socks5AddressType,
    Socks5AsyncAuther,
    Socks5Auther,
    Socks5AuthMethod,
    Socks5AuthReply,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersions,
)
from soxy._utils import (
    check_protocol_version,
    port_from_bytes,
    port_to_bytes,
)
from soxy._wrappers import auther_wrapper, resolver_wrapper


class _BaseSocks(
    ABC,
):
    def __init__(
        self,
        resolver: Resolver | None = None,
    ) -> None:
        self._resolver: typing.Callable[[str], typing.Awaitable[IPv4Address | None]] | None = (
            (resolver_wrapper(resolver)) if resolver else None
        )

    @abstractmethod
    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        pass

    @abstractmethod
    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        pass

    @abstractmethod
    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[Address, str | None]: ...


class Socks4(
    _BaseSocks,
):
    def __init__(
        self,
        auther: Socks4Auther | Socks4AsyncAuther | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self._auther: Socks4AsyncAuther | None = (
            auther_wrapper(auther) if auther else None  # type: ignore[assignment]
        )
        super().__init__(
            resolver=resolver,
        )

    async def send(
        self,
        client: Connection,
        reply: Socks4Reply,
        destination: Address,
    ) -> None:
        await client.write(
            bytes([0, reply.value]) + port_to_bytes(destination.port) + destination.ip.packed,
        )
        logger.info(f'{client} SOCKS4 response: {reply.name}')

    async def reject(
        self,
        client: Connection,
        reply: Socks4Reply = Socks4Reply.REJECTED,
        destination: Address | None = None,
    ) -> RejectError:
        if destination is None:
            destination = Address(ip=IPv4Address(1), port=0)
        await self.send(
            client=client,
            reply=reply,
            destination=destination,
        )
        return RejectError(address=destination)

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await self.reject(
            client=client,
            destination=destination,
        )

    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await self.send(
            client=client,
            reply=Socks4Reply.GRANTED,
            destination=destination,
        )

    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await self.reject(
            client=client,
            destination=destination,
        )

    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[Address, str | None]:
        check_protocol_version(data, SocksVersions.SOCKS4)
        if data[-1] != 0:
            raise PackageError(data)
        try:
            command = Socks4Command(data[1])
        except ValueError as exc:
            raise await self.reject(client) from exc
        if command is Socks4Command.BIND:
            raise await self.reject(client)
        destination = socks4_extract_destination(data)
        if len(data) == 9:  # noqa: PLR2004
            if self._auther:
                raise await self.reject(
                    client,
                    destination=destination,
                )
            return destination, None
        is_socks4a = isinstance(destination.ip, IPv4Address) and destination.ip <= IPv4Address(0xFF)
        username, domain_name = socks4_extract_from_tail(
            data=data,
            is_socks4a=is_socks4a,
        )
        if not is_socks4a:
            await self._authorization(
                client=client,
                username=username,
                destination=destination,
            )
            return destination, None
        if not domain_name or (self._resolver is None) or (domain_name is None):
            raise await self.reject(client)
        if (
            resolved := await self._resolver(
                domain_name,
            )
        ) is None:
            raise await self.reject(client)
        destination = Address(
            ip=resolved,
            port=destination.port,
        )
        await self._authorization(
            client=client,
            username=username,
            destination=destination,
        )
        return destination, domain_name

    async def _authorization(
        self,
        client: Connection,
        username: str | None,
        destination: Address,
    ) -> None:
        if username and not self._auther:
            raise await self.reject(
                client,
                reply=Socks4Reply.IDENTD_NOT_REACHABLE,
                destination=destination,
            )
        if not username:
            if self._auther:
                raise await self.reject(
                    client,
                    reply=Socks4Reply.IDENTD_REJECTED,
                    destination=destination,
                )
            return
        if self._auther is None:
            raise RuntimeError
        is_auth = await self._auther(username)
        if is_auth is True:
            logger.info(f'{self} {username} authorized')
            return
        logger.info(f'{self} fail to authorize {username}')
        raise await self.reject(
            client,
            reply=Socks4Reply.IDENTD_REJECTED,
            destination=destination,
        )


class Socks5(
    _BaseSocks,
):
    def __init__(
        self,
        auther: Socks5Auther | Socks5AsyncAuther | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        super().__init__(
            resolver=resolver,
        )
        self._auther: Socks5AsyncAuther | None = (
            auther_wrapper(auther) if auther else None  # type: ignore[assignment]
        )
        self._allowed_auth_method = Socks5AuthMethod.USERNAME if auther else Socks5AuthMethod.NO_AUTHENTICATION

    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[Address, str | None]:
        await self._greetings(client, data)
        if self._auther:
            await self._authorization(client)
        return await self._connect(client)

    async def reject(
        self,
        reply: Socks5ConnectionReply,
        client: Connection,
        address: str | IPv4Address | IPv6Address,
        port: int,
    ) -> RejectError:
        await client.write(
            socks5_connect_pack_response(
                reply,
                address=address,
                port=port,
            ),
        )
        return RejectError(
            address=(
                Address(ip=address, port=port)
                if not isinstance(address, str)
                else Address(ip=IPv4Address(0), port=port)
            ),
        )

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await self.reject(
            reply=Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET,
            client=client,
            address=destination.ip,
            port=destination.port,
        )

    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await client.write(
            socks5_connect_pack_response(
                Socks5ConnectionReply.SUCCEEDED,
                address=destination.ip,
                port=destination.port,
            ),
        )

    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await client.write(
            socks5_connect_pack_response(
                Socks5ConnectionReply.HOST_UNREACHABLE,
                address=destination.ip,
                port=destination.port,
            ),
        )

    async def _greetings(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        check_protocol_version(data, SocksVersions.SOCKS5)
        try:
            auth_methods_num = data[1]
            auth_methods = [Socks5AuthMethod(raw_method) for raw_method in list(data[2:])]
        except (IndexError, ValueError) as exc:
            raise PackageError(data) from exc
        if auth_methods_num != len(auth_methods):
            raise PackageError(data)
        if self._allowed_auth_method not in auth_methods:
            await client.write(
                socks5_greetings_pack_response(Socks5AuthMethod.NO_ACCEPTABLE),
            )
            raise PackageError(
                data,
            )
        await client.write(
            socks5_greetings_pack_response(
                (Socks5AuthMethod.USERNAME if self._auther else Socks5AuthMethod.NO_AUTHENTICATION),
            ),
        )

    async def _authorization(
        self,
        client: Connection,
    ) -> None:
        data = await client.read()
        if not data:
            return
        try:
            auth_version = data[0]
            username_len = data[1]
            username = data[2 : 2 + username_len].decode()
            password_len = data[2 + username_len]
            password = data[3 + username_len : 3 + username_len + password_len].decode()
        except (IndexError, UnicodeError) as exc:
            raise PackageError(data) from exc
        if auth_version != 1:
            raise PackageError(data)
        if self._auther is None:
            raise RuntimeError
        is_auth = await self._auther(username, password)
        if is_auth:
            logger.info(f'{self} {username} authorized')
            return
        logger.info(f'{self} fail to authorize {username}')
        await client.write(socks5_authorization_pack_response(is_auth))

    async def _connect(
        self,
        client: Connection,
    ) -> tuple[Address, str | None]:
        data = await client.read()
        check_protocol_version(data, SocksVersions.SOCKS5)
        domain_name = None
        try:
            destination, domain_name = await self._connect_make_destination(
                client=client,
                data=data,
            )
        except (IndexError, UnicodeError) as exc:
            raise PackageError(data) from exc
        except RejectError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                client=client,
                address=exc.address.ip,
                port=exc.address.port,
            ) from exc
        except ResolveDomainError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                client=client,
                address=exc.domain,
                port=exc.port,
            ) from exc
        try:
            command = Socks5Command(data[1])
        except ValueError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                address=destination.ip,
                port=destination.port,
            ) from exc
        if command is not Socks5Command.CONNECT:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                address=destination.ip,
                port=destination.port,
            )
        return destination, domain_name

    async def _connect_make_destination(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[Address, str | None]:
        address_type = Socks5AddressType(data[3])
        port = port_from_bytes(data[-2:])
        if address_type == Socks5AddressType.IPV6:
            try:
                raw_address = data[4 : 4 + IPV6LENGTH // 8]
            except IndexError as exc:
                raise PackageError(data) from exc
            return (
                Address(
                    ip=IPv6Address(raw_address),
                    port=port,
                ),
                None,
            )
        if address_type == Socks5AddressType.DOMAIN:
            domain_name = data[5 : 6 + data[4]].decode()
            if not self._resolver:
                raise await self.reject(
                    reply=Socks5ConnectionReply.ADDRESS_TYPE_NOT_SUPPORTED,
                    client=client,
                    address=domain_name,
                    port=port,
                )
            if resolved := await self._resolver(
                domain_name,
            ):
                return (
                    Address(
                        ip=resolved,
                        port=port,
                    ),
                    domain_name,
                )
            raise await self.reject(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                client=client,
                address=domain_name,
                port=port,
            )
        return (
            Address(
                ip=IPv4Address(data[4 : 4 + IPV4LENGTH // 8]),
                port=port,
            ),
            None,
        )


def socks4_extract_destination(
    data: bytes,
) -> Address:
    try:
        port, raw_address = struct.unpack('!HI', data[2:8])
    except (struct.error, IndexError) as exc:
        raise PackageError(data) from exc
    return Address(
        ip=IPv4Address(raw_address),
        port=port,
    )


def socks4_extract_from_tail(
    data: bytes,
    is_socks4a: bool,
) -> tuple[str | None, str | None]:
    tail = data[8:-1]
    username_bytes: bytes | None
    domain_bytes: bytes | None
    if b'\x00' in tail:
        try:
            username_bytes, domain_bytes = tail.split(b'\x00')
        except (ValueError, IndexError) as exc:
            raise PackageError(tail) from exc
    else:
        username_bytes, domain_bytes = (tail, None) if not is_socks4a else (None, tail)
    if not is_socks4a and domain_bytes:
        raise PackageError(data)
    try:
        username = username_bytes.decode() if username_bytes else None
        domain_name = domain_bytes.decode() if domain_bytes else None
    except UnicodeError as exc:
        raise PackageError(data) from exc
    return username, domain_name


def socks5_greetings_pack_response(
    auth_method: Socks5AuthMethod,
) -> bytes:
    return bytes([SocksVersions.SOCKS5.value, auth_method.value])


def socks5_authorization_pack_response(
    status: bool,
) -> bytes:
    reply = Socks5AuthReply.SUCCESS if status is True else Socks5AuthReply.FAIL
    return bytes([1, reply.value])


def socks5_connect_pack_response(
    reply: Socks5ConnectionReply,
    address: str | IPv4Address | IPv6Address,
    port: int,
) -> bytes:
    response = bytes([SocksVersions.SOCKS5.value, reply.value, 0])
    if isinstance(address, IPv4Address):
        response += bytes([Socks5AddressType.IPV4.value]) + address.packed
    if isinstance(address, IPv6Address):
        response += bytes([Socks5AddressType.IPV6.value]) + address.packed
    if isinstance(address, str):
        address_types = Socks5AddressType.DOMAIN
        response += bytes([address_types.value, len(address)]) + address.encode()
    return response + port_to_bytes(port)
