from asyncio import StreamReader, StreamWriter, open_connection
from logging import getLogger
from socket import gaierror
from typing import Any, Callable, Optional, Sequence, Tuple

from soxyproxy.connections import SocksConnection
from soxyproxy.consts import Socks5AuthMethod, Socks5ConnectionReply
from soxyproxy.exceptions import SocksConnectionError, SocksError
from soxyproxy.internal.authers import check_authers
from soxyproxy.internal.socks5 import socks5_raise_for_proxy_ruleset
from soxyproxy.models.ruleset import RuleSet
from soxyproxy.models.socks5 import connection, handshake, username_auth
from soxyproxy.server import ServerBase

logger = getLogger(__name__)


class Socks5(ServerBase):
    def __init__(
        self,
        ruleset: RuleSet = RuleSet(),
        authers: Sequence[Callable[[str, str], Optional[bool]]] = tuple(),
    ) -> None:
        super().__init__(ruleset=ruleset)
        self.authers = authers
        self.auth_methods = Socks5AuthMethod.USERNAME if authers else Socks5AuthMethod.NO_AUTHENTICATION

    async def proxy_handshake(
        self,
        client: SocksConnection,
    ) -> None:
        request_raw = await client.reader.read(512)
        request = handshake.RequestModel.load(client, request_raw)
        logger.debug(f"{client} -> {request.json()}")

        auth = Socks5AuthMethod.NO_ACCEPTABLE
        if self.auth_methods in request.auth_methods:
            auth = self.auth_methods

        response = handshake.ResponseModel(auth_method=auth)

        client.writer.write(response.dump())
        logger.debug(f"{client} <- {response.json()}")

        if auth is Socks5AuthMethod.NO_ACCEPTABLE:
            raise SocksError(client)

    async def proxy_auth(
        self,
        client: SocksConnection,
    ) -> Optional[username_auth.RequestModel]:
        if self.auth_methods is Socks5AuthMethod.NO_AUTHENTICATION:
            return None
        request_raw = await client.reader.read(128)
        request = username_auth.RequestModel.load(client, request_raw)
        logger.debug(f"{client} -> {request.json().replace(request.password, '***')}")

        auth_success = check_authers(request.username, request.password, self.authers)
        response = username_auth.ResponseModel(status=auth_success)

        client.writer.write(response.dump())
        logger.debug(f"{client} <- {response.json()}")

        if not auth_success:
            raise ConnectionError("authorization failed")

        return request

    async def proxy_connect(  # type: ignore
        self,
        client: SocksConnection,
        **kwargs,
    ) -> Tuple[StreamReader, StreamWriter]:
        client = SocksConnection(reader=client.reader, writer=client.writer)

        auth_request: Optional[username_auth.RequestModel] = kwargs.get("auth_request")
        request_raw = await client.reader.read(512)

        try:
            request = connection.RequestModel.load(client, request_raw)
            logger.debug(f"{client} -> {request.json()}")
        except gaierror as err:
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                address=connection.extract_domain_name(request_raw),
                port=connection.extract_port(request_raw),
            )
            client.writer.write(response.dump())
            logger.debug(f"{client} <- {response.json()}")
            raise SocksError(client, "fsdeasca") from err

        socks5_raise_for_proxy_ruleset(
            ruleset=self.ruleset,
            client=client,
            request=request,
            user=auth_request.username if auth_request else None,
        )

        remote_reader, remote_writer = await self._open_remote_connection(client=client, request=request)
        response = connection.ResponseModel(
            reply=Socks5ConnectionReply.SUCCEEDED,
            address=request.address,
            port=request.port,
        )
        client.writer.write(response.dump())
        logger.debug(f"{client} <- {response.json()}")

        return remote_reader, remote_writer

    async def _start_interaction(
        self,
        client: SocksConnection,
        **kwargs: Any,
    ) -> None:
        await self.proxy_handshake(client=client)
        auth_request = await self.proxy_auth(client=client)
        await super()._start_interaction(client=client, auth_request=auth_request)

    @staticmethod
    async def _open_remote_connection(
        client: SocksConnection,
        **kwargs: Any,
    ) -> Tuple[StreamReader, StreamWriter]:
        request: connection.RequestModel = kwargs["request"]
        try:
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
            logger.debug(f"{client} -> {request.json()}")
        except TimeoutError as err:
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.TTL_EXPIRED,
                address=request.address,
                port=request.port,
            )
            client.writer.write(response.dump())
            raise SocksConnectionError(
                client=client,
                host=str(request.address),
                port=request.port,
            ) from err
        except ConnectionError as err:
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                address=request.domain if request.domain else request.address,
                port=request.port,
            )
            client.writer.write(response.dump())
            raise ConnectionError(err) from err
        except Exception as err:
            raise ValueError(err) from err
        return remote_reader, remote_writer
