from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address

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
    Socks5AddressType,
    Socks5Auther,
    Socks5AuthMethod,
    Socks5AuthReply,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersions,
)
from soxyproxy._utils import (
    call_resolver,
    call_user_pass_auther,
    check_protocol_version,
    port_from_bytes,
    port_to_bytes,
)


class Socks5(
    BaseSocks,
):
    def __init__(
        self,
        auther: Socks5Auther | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        super().__init__(
            resolver=resolver,
        )
        self._auther = auther
        self._allowed_auth_method = (
            Socks5AuthMethod.USERNAME if auther else Socks5AuthMethod.NO_AUTHENTICATION
        )

    def _resolve_domain_name(
        self,
        name: str,
    ) -> IPv4Address:
        pass

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
            _connect_pack_response(
                reply,
                address=address,
                port=port,
            )
        )
        return RejectError(
            address=address,
            port=port,
        )

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await self.reject(
            reply=Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET,
            client=client,
            address=destination.address,
            port=destination.port,
        )

    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await client.write(
            _connect_pack_response(
                Socks5ConnectionReply.SUCCEEDED,
                address=destination.address,
                port=destination.port,
            )
        )

    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await client.write(
            _connect_pack_response(
                Socks5ConnectionReply.HOST_UNREACHABLE,
                address=destination.address,
                port=destination.port,
            )
        )

    async def _greetings(
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
            raise PackageError(data) from exc
        if auth_methods_num != len(auth_methods):
            raise PackageError(data)
        if self._allowed_auth_method not in auth_methods:
            await client.write(_greetings_pack_response(Socks5AuthMethod.NO_ACCEPTABLE))
            raise PackageError(data)
        await client.write(
            _greetings_pack_response(
                Socks5AuthMethod.USERNAME
                if self._auther
                else Socks5AuthMethod.NO_AUTHENTICATION
            ),
        )

    async def _authorization(
        self,
        client: Connection,
    ):
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
        try:
            status = await call_user_pass_auther(self._auther, username, password)
        except AuthorizationError:
            logger.info(f"{self} fail to authorize {username}")
        logger.info(f"{self} {username} authorized")
        await client.write(_authorization_pack_response(status))

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
        except (RejectError, ResolveDomainError) as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                client=client,
                address=exc.address,
                port=exc.port,
            ) from exc
        try:
            command = Socks5Command(data[1])
        except ValueError as exc:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                address=destination.address,
                port=destination.port,
            ) from exc
        if command is not Socks5Command.CONNECT:
            raise await self.reject(
                reply=Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
                client=client,
                address=destination.address,
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
                    address=IPv6Address(raw_address),
                    port=port,
                ),
                None,
            )
        if address_type == Socks5AddressType.DOMAIN:
            domain_name = data[5 : 5 + data[4]].decode()
            if not self._resolver:
                raise await self.reject(
                    reply=Socks5ConnectionReply.ADDRESS_TYPE_NOT_SUPPORTED,
                    client=client,
                    address=domain_name,
                    port=port,
                )
            try:
                return (
                    Address(
                        address=await call_resolver(
                            self._resolve_domain_name,
                            domain_name,
                        ),
                        port=port,
                    ),
                    domain_name,
                )
            except ResolveDomainError as exc:
                raise await self.reject(
                    reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                    client=client,
                    address=domain_name,
                    port=port,
                ) from exc
        return (
            Address(
                address=IPv4Address(data[4 : 4 + IPV4LENGTH // 8]),
                port=port,
            ),
            None,
        )


def _greetings_pack_response(
    auth_method: Socks5AuthMethod,
) -> bytes:
    return bytes([SocksVersions.SOCKS5.value, auth_method.value])


def _authorization_pack_response(
    status: bool,
) -> bytes:
    reply = Socks5AuthReply.SUCCESS if status is True else Socks5AuthReply.FAIL
    return bytes([1, reply.value])


def _connect_pack_response(
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
