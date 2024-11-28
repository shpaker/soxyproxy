import struct
from ipaddress import IPv4Address

from soxyproxy._base import BaseSocks
from soxyproxy._errors import (
    PackageError,
    RejectError,
    ResolveDomainError,
    AuthorizationError,
)
from soxyproxy._logger import logger
from soxyproxy._types import (
    Connection,
    Destination,
    Socks4Command,
    Socks4Reply,
    SocksVersions,
    Socks4Auther,
    DomainNameResolver,
)
from soxyproxy._utils import (
    check_protocol_version,
    port_to_bytes,
    call_domain_names_resolver,
    call_user_auther,
)


def _pack_response(
    reply: Socks4Reply,
    address: IPv4Address,
    port: int,
) -> bytes:
    return bytes([0, reply.value]) + port_to_bytes(port) + address.packed


class Socks4(
    BaseSocks,
):
    def __init__(
        self,
        auther: Socks4Auther | None = None,
        domain_names_resolver: DomainNameResolver | None = None,
    ) -> None:
        self._auther = auther
        super().__init__(
            domain_names_resolver=domain_names_resolver,
        )

    async def reject(
        self,
        client: Connection,
        destination: Destination = Destination(IPv4Address(0), 0),
    ) -> RejectError:
        await client.write(
            _pack_response(
                reply=Socks4Reply.REJECTED,
                address=destination.address,
                port=destination.port,
            )
        )
        logger.info(f"{client} SOCKS4 request rejected or failed")
        return RejectError(
            address=destination.address,
            port=destination.port,
        )

    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await client.write(
            _pack_response(
                Socks4Reply.GRANTED,
                address=destination.address,
                port=destination.port,
            )
        )
        logger.info(f"{client} SOCKS4 request granted")

    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await self.reject(
            client=client,
            destination=destination,
        )

    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Destination:
        check_protocol_version(data, SocksVersions.SOCKS4)
        if data[-1] != 0:
            raise PackageError(data)
        try:
            command = Socks4Command(data[1])
        except ValueError as exc:
            raise await self.reject(client) from exc
        if command is Socks4Command.BIND:
            raise await self.reject(client)
        try:
            port, raw_address = struct.unpack("!HI", data[2:8])
        except (struct.error, IndexError) as exc:
            raise await self.reject(client) from exc
        with_domain = raw_address <= 0xFF
        address = IPv4Address(raw_address)
        if len(data) == 9:
            destination = Destination(
                address=address,
                port=port,
            )
            if self._auther:
                raise await self.reject(
                    client,
                    destination=destination,
                )
            return destination
        tail_bytes = data[8:-1]
        if b"\x00" in tail_bytes:
            username_bytes, domain_bytes = data[8:-1].split(b"\x00")
        else:
            username_bytes, domain_bytes = (
                (tail_bytes, None) if not with_domain else (None, tail_bytes)
            )
        if not (bool(self._auther) != bool(username_bytes)):
            raise await self.reject(client, Destination(address, port))
        if username_bytes is not None:
            await self._authorization(
                client=client,
                data=username_bytes,
            )
        if not with_domain:
            if domain_bytes:
                raise await self.reject(client)
            return Destination(
                address=address,
                port=port,
            )
        if not self._domain_names_resolver and domain_bytes:
            raise await self.reject(client)
        try:
            domain = domain_bytes.decode()
        except UnicodeError as exc:
            raise await self.reject(client) from exc
        try:
            resolved = await call_domain_names_resolver(
                self._domain_names_resolver,
                name=domain,
            )
        except ResolveDomainError as exc:
            raise await self.reject(client) from exc
        return Destination(
            address=resolved,
            port=port,
        )

    async def _authorization(
        self,
        client: Connection,
        data: bytes,
    ) -> None:
        try:
            username = data.decode()
        except UnicodeError as exc:
            raise await self.reject(client) from exc
        try:
            await call_user_auther(
                auther=self._auther,
                username=username,
            )
        except AuthorizationError as exc:
            raise await self.reject(client) from exc
