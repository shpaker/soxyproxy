import socket
from asyncio import StreamReader, StreamWriter, open_connection
from logging import getLogger
from typing import Optional, Tuple, Callable

from soxyproxy.consts import Socks5AuthMethod, Socks5ConnectionReply
from soxyproxy.models.ruleset import RuleSet
from soxyproxy.models.socks5 import handshake, connection, username_auth
from soxyproxy.server import ServerBase

logger = getLogger(__name__)


class Socks5(ServerBase):
    def __init__(
        self,
        ruleset: RuleSet = RuleSet(),
        auther: Optional[Callable[[str, str], Optional[bool]]] = None,
    ) -> None:
        super().__init__(ruleset=ruleset)
        self.auther = auther
        self.auth_methods = (
            Socks5AuthMethod.USERNAME if auther else Socks5AuthMethod.NO_AUTHENTICATION
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
    ) -> None:

        host, port = client_writer.get_extra_info("peername")

        if self.auth_methods is Socks5AuthMethod.NO_AUTHENTICATION:
            return None

        if self.auther is not None:
            request_raw = await client_reader.read(128)
            request = username_auth.RequestModel.loads(request_raw)

            logger.debug(f"{host}:{port} -> {request}")
            # self._log_message(client_writer, request)

            auth_success = self.auther(request.username, request.password)

            if auth_success is None:
                auth_success = False

            response = username_auth.ResponseModel(status=auth_success)

            logger.debug(f"{host}:{port} <- {response}")

            if not auth_success:
                client_writer.write(response.dumps())
                raise ConnectionError("authorization failed")

            client_writer.write(response.dumps())

    async def connect(  # type: ignore
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> Tuple[StreamReader, StreamWriter]:
        host, port = client_writer.get_extra_info("peername")

        request_raw = await client_reader.read(512)
        response: Optional[connection.ResponseModel] = None

        try:
            request = connection.RequestModel.loads(request_raw)

            logger.debug(f"{host}:{port} -> {request}")
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.SUCCEEDED,
                address=request.address,
                port=request.port,
            )
            return remote_reader, remote_writer
        except socket.gaierror:
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                address=connection.extract_domain_name(request_raw),
                port=connection.extract_port(request_raw),
            )
        except (OSError, TimeoutError):
            response = connection.ResponseModel(
                reply=Socks5ConnectionReply.HOST_UNREACHABLE,
                address=connection.extract_address(request_raw),
                port=connection.extract_port(request_raw),
            )
        finally:
            if response:
                logger.debug(f"{host}:{port} -> {response}")
                client_writer.write(response.dumps())

            if response and response.reply is not Socks5ConnectionReply.SUCCEEDED:
                raise ConnectionError(response.reply.name)

    async def serve_client(
        self, client_reader: StreamReader, client_writer: StreamWriter
    ) -> None:
        await self.handshake(
            client_reader=client_reader,
            client_writer=client_writer,
        )
        await self.auth(
            client_reader=client_reader,
            client_writer=client_writer,
        )
        await super().serve_client(
            client_reader=client_reader,
            client_writer=client_writer,
        )
