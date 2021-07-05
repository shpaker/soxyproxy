import socket
from asyncio import StreamReader, StreamWriter, open_connection
from logging import getLogger
from typing import Optional, Tuple

from soxyproxy.consts import Socks5AuthMethod, Socks5ConnectionReplies
from soxyproxy.models.socks5 import (
    handshake_request,
    handshake_response,
)
from soxyproxy.models.socks5.connection_request_message import (
    Socks5ConnectionRequestMessage,
)
from soxyproxy.models.socks5.connection_response_message import (
    Socks5ConnectionResponseMessage,
)
from soxyproxy.models.socks5.username_auth_request_message import (
    Socks5UsernameAuthRequestMessage,
)
from soxyproxy.models.socks5.username_auth_response_message import (
    Socks5UsernameAuthResponseMessage,
)
from soxyproxy.servers.server import ServerBase

logger = getLogger(__name__)


class Socks5(ServerBase):
    def __init__(
        self, username: Optional[str] = None, password: Optional[str] = None
    ) -> None:

        if username and not password or not username and password:
            raise KeyError

        self.username = username
        self.password = password
        self.auth_method = (
            Socks5AuthMethod.USERNAME
            if username
            else Socks5AuthMethod.NO_AUTHENTICATION
        )

    async def handshake(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> None:
        request_raw = await client_reader.read(512)
        request = handshake_request.RequestModel.loads(request_raw)
        host, port = client_writer.get_extra_info("peername")
        logger.debug(f"{host}:{port} -> {request.json()}")

        auth = Socks5AuthMethod.NO_ACCEPTABLE
        if self.auth_method in request.auth_methods:
            auth = self.auth_method

        response = handshake_response.ResponseModel(auth_method=auth)

        client_writer.write(response.dumps())
        logger.debug(f"{host}:{port} <- {response.json()}")

        if auth is Socks5AuthMethod.NO_ACCEPTABLE:
            raise ConnectionError(Socks5AuthMethod.NO_ACCEPTABLE.name)

    async def auth(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> Optional[Socks5UsernameAuthResponseMessage]:

        host, port = client_writer.get_extra_info("peername")

        if self.auth_method is Socks5AuthMethod.NO_AUTHENTICATION:
            return

        if self.auth_method is Socks5AuthMethod.USERNAME:
            request_raw = await client_reader.read(128)
            request = Socks5UsernameAuthRequestMessage.from_bytes(request_raw)

            logger.debug(f"{host}:{port} -> {request}")
            # self._log_message(client_writer, request)

            auth_success = (
                request.username == self.username and request.password == self.password
            )
            response = Socks5UsernameAuthResponseMessage(status=auth_success)

            logger.debug(f"{host}:{port} <- {response}")

            if not auth_success:
                client_writer.write(response.as_bytes)
                raise ConnectionError("authorization failed")

            client_writer.write(response.as_bytes)

    async def connect(
        self, client_reader: StreamReader, client_writer: StreamWriter
    ) -> Tuple[StreamReader, StreamWriter]:
        host, port = client_writer.get_extra_info("peername")

        request_raw = await client_reader.read(512)
        response: Optional[Socks5ConnectionResponseMessage] = None

        try:
            request = Socks5ConnectionRequestMessage.from_bytes(request_raw)

            logger.debug(f"{host}:{port} -> {request}")
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
            response = Socks5ConnectionResponseMessage(
                reply=Socks5ConnectionReplies.SUCCEEDED,
                address=request.address,
                port=request.port,
            )
            return remote_reader, remote_writer
        except socket.gaierror:
            response = Socks5ConnectionResponseMessage(
                reply=Socks5ConnectionReplies.HOST_UNREACHABLE,
                address=Socks5ConnectionRequestMessage.get_domain_name_from_raw(
                    request_raw
                ),
                port=Socks5ConnectionRequestMessage.get_port_from_raw(request_raw),
            )
        except (OSError, TimeoutError):
            response = Socks5ConnectionResponseMessage(
                reply=Socks5ConnectionReplies.HOST_UNREACHABLE,
                address=Socks5ConnectionRequestMessage.get_address_from_raw(
                    request_raw
                ),
                port=Socks5ConnectionRequestMessage.get_port_from_raw(request_raw),
            )
        finally:
            if response:
                logger.debug(f"{host}:{port} -> {response}")
                client_writer.write(response.as_bytes)

            if response and response.reply is not Socks5ConnectionReplies.SUCCEEDED:
                raise ConnectionError(response.reply.name)

    async def serve_client(
        self, client_reader: StreamReader, client_writer: StreamWriter
    ):
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
