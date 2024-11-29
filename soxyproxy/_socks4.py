import struct
from ipaddress import IPv4Address

from soxyproxy._base import BaseSocks
from soxyproxy._errors import (
    AuthorizationError,
    PackageError,
    RejectError,
    ResolveDomainError,
)
from soxyproxy._logger import logger
from soxyproxy._types import (
    Connection,
    Destination,
    DomainNameResolver,
    Socks4Auther,
    Socks4Command,
    Socks4Reply,
    SocksVersions,
)
from soxyproxy._utils import (
    call_domain_names_resolver,
    call_user_auther,
    check_protocol_version,
    port_to_bytes,
)


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

    async def send(
        self,
        client: Connection,
        reply: Socks4Reply,
        address: IPv4Address,
        port: int,
    ) -> None:
        await client.write(
            bytes([0, reply.value]) + port_to_bytes(port) + address.packed
        )
        logger.info(f'{client} SOCKS4 response: {reply.name}')

    async def reject(
        self,
        client: Connection,
        reply: Socks4Reply = Socks4Reply.REJECTED,
        address: IPv4Address = IPv4Address(0),  # noqa: B008
        port: int = 0,
    ) -> RejectError:
        await self.send(
            client=client,
            reply=reply,
            address=address,
            port=port,
        )
        return RejectError(
            address=address,
            port=port,
        )

    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await self.send(
            client=client,
            reply=Socks4Reply.GRANTED,
            address=destination.address,
            port=destination.port,
        )

    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> None:
        await self.reject(
            client=client,
            address=destination.address,
            port=destination.port,
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
        address, port = await self._extract_destination(client, data)
        if len(data) == 9:
            destination = Destination(
                address=address,
                port=port,
            )
            if self._auther:
                raise await self.reject(
                    client,
                    address=destination.address,
                    port=destination.port,
                )
            return destination
        is_socks4a = address <= IPv4Address(0xFF)
        username, domain = await self._extract_from_tail(
            client,
            data=data[9:-1],
            is_socks4a=is_socks4a,
            address=address,
            port=port,
        )
        if not is_socks4a:
            await self._authorization(
                client=client,
                username=username,
                address=address,
                port=port,
            )
            return Destination(
                address=address,
                port=port,
            )
        if not self._domain_names_resolver and domain:
            raise await self.reject(client)
        try:
            resolved = await call_domain_names_resolver(
                self._domain_names_resolver,
                name=domain,
            )
        except ResolveDomainError as exc:
            raise await self.reject(client) from exc
        await self._authorization(
            client=client,
            username=username,
            address=resolved,
            port=port,
        )
        return Destination(
            address=resolved,
            port=port,
        )

    async def _extract_destination(
        self,
        client: Connection,
        data: bytes,
    ) -> tuple[IPv4Address, int]:
        try:
            port, raw_address = struct.unpack('!HI', data[2:8])
        except (struct.error, IndexError) as exc:
            raise await self.reject(client) from exc
        return IPv4Address(raw_address), port

    async def _extract_from_tail(
        self,
        client: Connection,
        data: bytes,
        is_socks4a: bool,
        address: IPv4Address,
        port: int,
    ) -> tuple[str | None, str | None]:
        if b'\x00' in data:
            try:
                username_bytes, domain_bytes = data[8:-1].split(b'\x00')
            except (ValueError, IndexError) as exc:
                raise await self.reject(
                    client,
                    address=address,
                    port=port,
                ) from exc
        else:
            username_bytes, domain_bytes = (
                (data, None) if not is_socks4a else (None, data)
            )
        if not is_socks4a and domain_bytes:
            raise await self.reject(client)
        try:
            username = username_bytes.decode() if username_bytes else None
            domain = domain_bytes.decode() if domain_bytes else None
        except UnicodeError as exc:
            raise await self.reject(
                client,
                address=address,
                port=port,
            ) from exc
        return username, domain

    async def _authorization(
        self,
        client: Connection,
        username: str | None,
        address: IPv4Address,
        port: int,
    ) -> None:
        if username and not self._auther:
            raise await self.reject(
                client,
                reply=Socks4Reply.IDENTD_NOT_REACHABLE,
                address=address,
                port=port,
            )
        if not username:
            if self._auther:
                raise await self.reject(
                    client,
                    reply=Socks4Reply.IDENTD_REJECTED,
                    address=address,
                    port=port,
                )
            return
        try:
            await call_user_auther(
                auther=self._auther,
                username=username,
            )
        except AuthorizationError as exc:
            raise await self.reject(
                client,
                reply=Socks4Reply.IDENTD_REJECTED,
                address=address,
                port=port,
            ) from exc
