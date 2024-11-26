from collections.abc import Awaitable, Callable
from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
from socket import gaierror

from soxyproxy._base import BaseSocks
from soxyproxy._errors import (
    SocksPackageError,
    SocksRejectError,
)
from soxyproxy._types import (
    Connection,
    Destination,
    Socks5AddressType,
    Socks5AuthMethod,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersions,
)
from soxyproxy._utils import (
    check_protocol_version,
    port_from_bytes,
    port_to_bytes,
    resolve_host,
)


class Socks5(
    BaseSocks,
):
    def __init__(
        self,
        auther: Callable[[str, str], bool | Awaitable[bool]] | None = None,
    ) -> None:
        self._auther = auther
        self._auth_method = (
            Socks5AuthMethod.USERNAME
            if auther
            else Socks5AuthMethod.NO_AUTHENTICATION
        )

    async def reject(
        self,
        reply: Socks5ConnectionReply,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        await client.write(
            self._pack_connect_response(
                reply,
                destination=destination,
            )
        )
        return SocksRejectError(destination)

    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await client.write(
            self._pack_connect_response(
                Socks5ConnectionReply.SUCCEEDED,
                destination=destination,
            )
        )

    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await client.write(
            self._pack_connect_response(
                Socks5ConnectionReply.HOST_UNREACHABLE,
                destination=destination,
            )
        )

    @staticmethod
    def _pack_handshake_response(
        auth_method: Socks5AuthMethod,
    ) -> bytes:
        return bytes([SocksVersions.SOCKS5.value, auth_method.value])

    @staticmethod
    def _pack_connect_response(
        reply: Socks5ConnectionReply,
        destination: Destination,
    ) -> bytes:
        response = bytes([SocksVersions.SOCKS5.value, reply.value, 0])
        if isinstance(destination.address, IPv4Address):
            response += (
                bytes([Socks5AddressType.IPV4.value])
                + destination.address.packed
            )
        if isinstance(destination.address, IPv6Address):
            response += (
                bytes([Socks5AddressType.IPV6.value])
                + destination.address.packed
            )
        if isinstance(destination.address, str):
            address_types = Socks5AddressType.DOMAIN
            response += (
                bytes([address_types.value, len(destination)])
                + destination.address.encode()
            )
        return response + port_to_bytes(destination.port)

    async def _choose_auth(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        check_protocol_version(data, SocksVersions.SOCKS5)
        try:
            auth_methods_num = data[1]
            auth_methods = [
                Socks5AuthMethod(raw_method) for raw_method in list(data[2:])
            ]
        except (IndexError, ValueError) as exc:
            raise SocksPackageError(data) from exc
        if auth_methods_num != len(auth_methods):
            raise SocksPackageError(data)
        if not (self._auth_method in auth_methods):
            await client.write(
                self._pack_handshake_response(Socks5AuthMethod.NO_ACCEPTABLE)
            )
            raise SocksRejectError
        await client.write(
            self._pack_handshake_response(self._auth_method),
        )

    async def _auth(
        self,
        client: Connection,
    ): ...

    @staticmethod
    def _make_destination(
        data: bytes,
    ) -> Destination:
        address_type = Socks5AddressType(data[3])
        port = port_from_bytes(data[-2:])
        if address_type == Socks5AddressType.IPV6:
            try:
                raw_address = data[4 : 4 + IPV6LENGTH // 8]
            except IndexError as exc:
                raise SocksPackageError(data) from exc
            return Destination(
                address=IPv6Address(raw_address),
                port=port,
            )
        if address_type == Socks5AddressType.DOMAIN:
            domain = data[5 : 5 + data[4]].decode()
            try:
                return Destination(
                    address=resolve_host(domain),
                    port=port,
                )
            except gaierror as exc:
                raise SocksRejectError(
                    destination=Destination(
                        address=domain,
                        port=port,
                    )
                ) from exc
        return Destination(
            address=IPv4Address(data[4 : 4 + IPV4LENGTH // 8]),
            port=port,
        )

    async def _connect(
        self,
        client: Connection,
    ) -> Destination:
        data = await client.read()
        check_protocol_version(data, SocksVersions.SOCKS5)
        try:
            destination = self._make_destination(data)
        except (IndexError, UnicodeError) as exc:
            raise SocksPackageError from exc
        except SocksRejectError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                client=client,
                destination=exc.destination,
            ) from exc
        try:
            command = Socks5Command(data[1])
        except ValueError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                destination=destination,
            ) from exc
        if command is not Socks5Command.CONNECT:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                destination=destination,
            )
        return destination

    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Destination:
        await self._choose_auth(client, data)
        if self._auth_method is not Socks5AuthMethod.NO_AUTHENTICATION:
            await self._auth(client)
        return await self._connect(client)
