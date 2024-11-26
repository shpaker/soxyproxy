import struct
from abc import ABC, abstractmethod
from ipaddress import IPv4Address
from socket import gaierror

from soxyproxy._base import BaseSocks
from soxyproxy._errors import (
    SocksIncorrectVersionError,
    SocksPackageError,
    SocksRejectError,
)
from soxyproxy._types import (
    Connection,
    Destination,
    Socks4Command,
    Socks4Reply,
    SocksVersions,
)
from soxyproxy._utils import (
    check_protocol_version,
    port_to_bytes,
    resolve_host,
)


class BaseSocks4(
    BaseSocks,
    ABC,
):
    @abstractmethod
    async def _unpack_request(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[Socks4Command, Destination]:
        raise NotImplementedError

    @staticmethod
    def _pack_response(
        reply: Socks4Reply,
        destination: Destination,
    ) -> bytes:
        return (
            bytes([0, reply.value])
            + port_to_bytes(destination.port)
            + destination.address.packed
        )

    async def reject(
        self,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        await client.write(
            self._pack_response(
                Socks4Reply.REJECTED,
                destination=destination,
            )
        )
        return SocksRejectError(destination)

    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        pass

    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        pass

    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Destination:
        check_protocol_version(data, SocksVersions.SOCKS4)
        if data[0] != SocksVersions.SOCKS4:
            raise SocksIncorrectVersionError(data)
        if data[-1] != 0:
            raise SocksPackageError(data)
        try:
            command, destination = await self._unpack_request(
                client=client,
                data=data,
            )
        except SocksRejectError as exc:
            await client.write(
                self._pack_response(
                    reply=Socks4Reply.REJECTED,
                    destination=exc.destination,
                )
            )
            raise
        if command is Socks4Command.BIND:
            raise await self.reject(client, destination)
        await client.write(
            self._pack_response(
                Socks4Reply.GRANTED,
                destination=destination,
            )
        )
        return destination


class Socks4(
    BaseSocks4,
):
    async def _unpack_request(
        self,
        client: Connection,  # noqa: ARG002
        data: bytes,
    ) -> tuple[Socks4Command, Destination]:
        try:
            raw_command, port, raw_address = struct.unpack('!BHI', data[1:-1])
        except struct.error as exc:
            raise SocksPackageError(data) from exc
        try:
            address = IPv4Address(raw_address)
            command = Socks4Command(raw_command)
        except ValueError as exc:
            raise SocksPackageError(data) from exc
        return command, Destination(host=address, port=port)


class Socks4A(
    BaseSocks4,
):
    async def _unpack_request(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[int, Destination]:
        if len(data) <= 7:
            raise SocksPackageError(data)
        try:
            raw_command, port, raw_address = struct.unpack('!BHI', data[1:8])
        except struct.error as exc:
            raise SocksPackageError(data) from exc
        if data[8] != 0:
            raise SocksPackageError(data)
        try:
            zero_address = IPv4Address(raw_address)
            command = Socks4Command(raw_command)
        except ValueError as exc:
            raise SocksPackageError(data) from exc
        destination = Destination(host=zero_address, port=port)
        if not (0 < raw_address <= 0xFF):
            raise await self.reject(client, destination)
        try:
            domain = data[9:-1].decode()
        except UnicodeError as exc:
            raise SocksPackageError(data) from exc
        try:
            address = resolve_host(domain)
        except gaierror as exc:
            raise await self.reject(client, destination) from exc
        return command, Destination(host=IPv4Address(address), port=port)
