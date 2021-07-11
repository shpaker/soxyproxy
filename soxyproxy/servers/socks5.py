from asyncio import StreamReader, StreamWriter, open_connection
from ipaddress import IPv4Address, IPv6Address
from logging import getLogger
from socket import gaierror
from typing import Any, Callable, Optional, Sequence, Tuple, Union

from soxyproxy.consts import Socks5AuthMethod, Socks5ConnectionReply
from soxyproxy.internal.authers import check_authers
from soxyproxy.internal.ruleset import check_proxy_rules
from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import RuleAction, RuleSet
from soxyproxy.models.socks5 import connection, handshake, username_auth
from soxyproxy.servers.base import ServerBase

logger = getLogger(__name__)


class Socks5(ServerBase):
    def __init__(
        self,
        ruleset: RuleSet = RuleSet(),
        authers: Sequence[Callable[[str, str], Optional[bool]]] = tuple(),
    ) -> None:
        super().__init__(ruleset=ruleset)
        self.authers = authers
        self.auth_methods = (
            Socks5AuthMethod.USERNAME if authers else Socks5AuthMethod.NO_AUTHENTICATION
        )

    async def handshake(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> None:
        request_raw = await client_reader.read(512)
        request = handshake.RequestModel.loads(request_raw)
        host, port = client_writer.get_extra_info("peername")
        logger.debug(f"{host}:{port} -> {request.json()}")

        auth = Socks5AuthMethod.NO_ACCEPTABLE
        if self.auth_methods in request.auth_methods:
            auth = self.auth_methods

        response = handshake.ResponseModel(auth_method=auth)

        client_writer.write(response.dumps())
        logger.debug(f"{host}:{port} <- {response.json()}")

        if auth is Socks5AuthMethod.NO_ACCEPTABLE:
            raise ConnectionError(Socks5AuthMethod.NO_ACCEPTABLE.name)

    async def auth(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> Optional[username_auth.RequestModel]:
        if self.auth_methods is Socks5AuthMethod.NO_AUTHENTICATION:
            return None
        if not self.authers:
            return None
        request_raw = await client_reader.read(128)
        client = ClientModel.from_writer(client_writer)
        request = username_auth.RequestModel.loads(request_raw)
        logger.debug(f"{client.host}:{client.port} -> {request}")

        auth_success = check_authers(request.username, request.password, self.authers)

        if auth_success is None:
            auth_success = False

        response = username_auth.ResponseModel(status=auth_success)

        logger.debug(f"{client.host}:{client.port} <- {response}")

        if not auth_success:
            client_writer.write(response.dumps())
            raise ConnectionError("authorization failed")

        client_writer.write(response.dumps())
        return request

    async def connect(  # type: ignore
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        **kwargs,
    ) -> Tuple[StreamReader, StreamWriter]:
        auth_request: Optional[username_auth.RequestModel] = kwargs.get("auth_request")
        request_raw = await client_reader.read(512)
        client = ClientModel.from_writer(client_writer)
        try:
            request = connection.RequestModel.loads(request_raw)
            matched_rule = check_proxy_rules(
                ruleset=self.ruleset,
                client=client,
                request_to=request.address,
                user=auth_request.username if auth_request else None,
            )
            if matched_rule and matched_rule.action is RuleAction.BLOCK:
                raise RuntimeError(
                    f"{client.host} ! connection blocked by rule: {matched_rule.json()}"
                )
            logger.debug(f"{client.host}:{client.port} -> {request}")
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
        except (ConnectionError, TimeoutError, gaierror) as err:
            address: Union[str, IPv4Address, IPv6Address] = connection.extract_address(
                request_raw
            )
            if isinstance(err, gaierror):
                address = connection.extract_domain_name(request_raw)
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                address=address,
                port=connection.extract_port(request_raw),
            )
            client_writer.write(response.dumps())
            raise ConnectionError(err) from err
        except RuntimeError as err:
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET,
                address=connection.extract_address(request_raw),
                port=connection.extract_port(request_raw),
            )
            client_writer.write(response.dumps())
            raise ConnectionError(err) from err
        except Exception as err:
            raise ValueError(err) from err
        response = connection.ResponseModel(
            reply=Socks5ConnectionReply.SUCCEEDED,
            address=request.address,
            port=request.port,
        )
        logger.debug(f"{client.host}:{client.port} -> {response}")
        client_writer.write(response.dumps())
        return remote_reader, remote_writer

    async def serve_client(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        **kwargs: Any,
    ) -> None:
        await self.handshake(
            client_reader=client_reader,
            client_writer=client_writer,
        )
        auth_request = await self.auth(
            client_reader=client_reader,
            client_writer=client_writer,
        )
        await super().serve_client(
            client_reader=client_reader,
            client_writer=client_writer,
            auth_request=auth_request,
        )
