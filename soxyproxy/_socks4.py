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
    Address,
    Connection,
    Resolver,
    Socks4Auther,
    Socks4Command,
    Socks4Reply,
    SocksVersions,
)
from soxyproxy._utils import (
    call_resolver,
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
        resolver: Resolver | None = None,
    ) -> None:
        self._auther = auther
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
            bytes([0, reply.value])
            + port_to_bytes(destination.port)
            + destination.address.packed
        )
        logger.info(f'{client} SOCKS4 response: {reply.name}')

    async def reject(
        self,
        client: Connection,
        reply: Socks4Reply = Socks4Reply.REJECTED,
        destination: Address | None = None,
    ) -> RejectError:
        if destination is None:
            destination = Address(address=IPv4Address(1), port=0)
        await self.send(
            client=client,
            reply=reply,
            destination=destination,
        )
        return RejectError(
            address=destination.address,
            port=destination.port,
        )

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
    ) -> Address:
        check_protocol_version(data, SocksVersions.SOCKS4)
        if data[-1] != 0:
            raise PackageError(data)
        try:
            command = Socks4Command(data[1])
        except ValueError as exc:
            raise await self.reject(client) from exc
        if command is Socks4Command.BIND:
            raise await self.reject(client)
        destination = await self._extract_destination(client, data)
        if len(data) == 9:
            if self._auther:
                raise await self.reject(
                    client,
                    destination=destination,
                )
            return destination
        is_socks4a = destination.address <= IPv4Address(0xFF)
        username, domain = await self._extract_from_tail(
            client,
            data=data[9:-1],
            is_socks4a=is_socks4a,
            destination=destination,
        )
        if not is_socks4a:
            await self._authorization(
                client=client,
                username=username,
                destination=destination,
            )
            return destination
        if not self._resolver and domain:
            raise await self.reject(client)
        try:
            resolved = await call_resolver(
                self._resolver,
                name=domain,
            )
        except ResolveDomainError as exc:
            raise await self.reject(client) from exc
        destination = Address(
            address=resolved,
            port=destination.port,
        )
        await self._authorization(
            client=client,
            username=username,
            destination=destination,
        )
        return destination

    async def _extract_destination(
        self,
        client: Connection,
        data: bytes,
    ) -> Address:
        try:
            port, raw_address = struct.unpack('!HI', data[2:8])
        except (struct.error, IndexError) as exc:
            raise await self.reject(client) from exc
        return Address(
            address=IPv4Address(raw_address),
            port=port,
        )

    async def _extract_from_tail(
        self,
        client: Connection,
        data: bytes,
        is_socks4a: bool,
        destination: Address,
    ) -> tuple[str | None, str | None]:
        if b'\x00' in data:
            try:
                username_bytes, domain_bytes = data[8:-1].split(b'\x00')
            except (ValueError, IndexError) as exc:
                raise await self.reject(
                    client,
                    destination=destination,
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
                destination=destination,
            ) from exc
        return username, domain

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
        try:
            await call_user_auther(
                auther=self._auther,
                username=username,
            )
            logger.info(f'{self} {username} authorized')
        except AuthorizationError as exc:
            logger.info(f'{self} fail to authorize {username}')
            raise await self.reject(
                client,
                reply=Socks4Reply.IDENTD_REJECTED,
                destination=destination,
            ) from exc
