import typing
from abc import ABC, abstractmethod

from soxy._errors import (
    AuthorizationError,
    RejectError,
)
from soxy._logger import logger
from soxy._packages import (
    Socks4Request,
    Socks4Response,
    Socks5AuthorizationRequest,
    Socks5AuthorizationResponse,
    Socks5ConnectionRequest,
    Socks5ConnectionResponse,
    Socks5GreetingRequest,
    Socks5GreetingResponse,
)
from soxy._types import (
    Address,
    Connection,
    Resolver,
    Socks4AsyncAuther,
    Socks4Auther,
    Socks4Command,
    Socks4Reply,
    Socks5AsyncAuther,
    Socks5Auther,
    Socks5AuthMethod,
    Socks5ConnectionReply,
)
from soxy._wrappers import auther_wrapper, resolver_wrapper

if typing.TYPE_CHECKING:
    from ipaddress import IPv4Address


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

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks4Response(
            client=client,
            reply=Socks4Reply.REJECTED,
            destination=destination,
        ).to_client()

    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks4Response(
            client=client,
            reply=Socks4Reply.GRANTED,
            destination=destination,
        ).to_client()

    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks4Response(
            client=client,
            reply=Socks4Reply.REJECTED,
            destination=destination,
        ).to_client()

    async def __call__(
        self,
        client: Connection,
    ) -> tuple[Address, str | None]:
        request = await Socks4Request.from_client(client)
        if request.command is Socks4Command.BIND:
            await Socks4Response(
                client=client,
                reply=Socks4Reply.REJECTED,
                destination=request.destination,
            ).to_client()
            raise RejectError(address=request.destination)
        if not request.is_socks4a:
            if self._auther:
                if not request.username:
                    await Socks4Response(
                        client=client,
                        reply=Socks4Reply.REJECTED,
                        destination=request.destination,
                    ).to_client()
                    raise RejectError(address=request.destination)
                await self._authorization(
                    client=client,
                    username=request.username,
                    destination=request.destination,
                )
            return request.destination, None
        if not (self._resolver and request.domain_name):
            await Socks4Response(
                client=client,
                reply=Socks4Reply.REJECTED,
                destination=request.destination,
            ).to_client()
            raise RejectError(address=request.destination)
        if (
            resolved := await self._resolver(
                request.domain_name,
            )
        ) is None:
            await Socks4Response(
                client=client,
                reply=Socks4Reply.REJECTED,
                destination=request.destination,
            ).to_client()
            raise RejectError(address=request.destination)
        destination = Address(
            ip=resolved,
            port=request.destination.port,
        )
        await self._authorization(
            client=client,
            username=request.username,
            destination=destination,
        )
        return destination, request.domain_name

    async def _authorization(
        self,
        client: Connection,
        username: str | None,
        destination: Address,
    ) -> None:
        if username and not self._auther:
            await Socks4Response(
                client=client,
                reply=Socks4Reply.IDENTD_NOT_REACHABLE,
                destination=destination,
            ).to_client()
            raise RejectError(address=destination)
        if not username:
            if self._auther:
                await Socks4Response(
                    client=client,
                    reply=Socks4Reply.IDENTD_REJECTED,
                    destination=destination,
                ).to_client()
                raise RejectError(address=destination)
            return
        if self._auther is None:
            raise RuntimeError
        if (await self._auther(username)) is False:
            logger.info(f'{self} fail to authorize {username}')
            await Socks4Response(
                client=client,
                reply=Socks4Reply.IDENTD_REJECTED,
                destination=destination,
            ).to_client()
            raise AuthorizationError(
                username=username,
            )
        logger.info(f'{self} {username} authorized')


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
    ) -> tuple[Address, str | None]:
        greetings_request = await Socks5GreetingRequest.from_client(client)
        greetings_response = self._greetings(
            request=greetings_request,
        )
        await greetings_response.to_client()
        if greetings_response.method is Socks5AuthMethod.NO_ACCEPTABLE:
            await Socks5ConnectionResponse(
                client=client,
                reply=Socks5ConnectionReply.CONNECTION_REFUSED,
            ).to_client()
            raise RejectError
        if self._auther:
            authorization_request = await Socks5AuthorizationRequest.from_client(client)
            response = await self._authorization(authorization_request)
            await response.to_client()
            if not response.is_success:
                raise AuthorizationError(
                    username=authorization_request.username,
                )
        try:
            data = await self._connect(
                await Socks5ConnectionRequest.from_client(client),
            )
        except RejectError as exc:
            await Socks5ConnectionResponse(
                client=client,
                reply=Socks5ConnectionReply.CONNECTION_REFUSED,
                destination=exc.address.ip,
                port=exc.address.port,
            ).to_client()
            raise
        return data

    async def ruleset_reject(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks5ConnectionResponse(
            client=client,
            reply=Socks5ConnectionReply.ADDRESS_TYPE_NOT_SUPPORTED,
            destination=destination.ip,
            port=destination.port,
        ).to_client()

    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks5ConnectionResponse(
            client=client,
            reply=Socks5ConnectionReply.SUCCEEDED,
            destination=destination.ip,
            port=destination.port,
        ).to_client()

    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        await Socks5ConnectionResponse(
            client=client,
            reply=Socks5ConnectionReply.HOST_UNREACHABLE,
            destination=destination.ip,
            port=destination.port,
        ).to_client()

    def _greetings(
        self,
        request: Socks5GreetingRequest,
    ) -> Socks5GreetingResponse:
        if self._allowed_auth_method not in request.methods:
            return Socks5GreetingResponse(
                client=request.client,
                method=Socks5AuthMethod.NO_ACCEPTABLE,
            )
        return Socks5GreetingResponse(
            client=request.client,
            method=(Socks5AuthMethod.USERNAME if self._auther else Socks5AuthMethod.NO_AUTHENTICATION),
        )

    async def _authorization(
        self,
        request: Socks5AuthorizationRequest,
    ) -> Socks5AuthorizationResponse:
        if self._auther is None:
            raise RuntimeError
        is_success = await self._auther(
            request.username,
            request.password,
        )
        response = Socks5AuthorizationResponse(
            client=request.client,
            is_success=is_success,
        )
        if is_success is True:
            logger.info(f'{self} {request.username} authorized')
        else:
            logger.info(f'{self} fail to authorize {request.username}')
        return response

    async def _connect(
        self,
        request: Socks5ConnectionRequest,
    ) -> tuple[Address, str | None]:
        if request.domain_name is None:
            if request.destination is None:
                raise RejectError
            return request.destination, None
        if self._resolver is None:
            raise RejectError
        if (
            resolved := await self._resolver(
                request.domain_name,
            )
        ) is None:
            raise RejectError
        return (
            Address(
                ip=resolved,
                port=request.port,
            ),
            request.domain_name,
        )
