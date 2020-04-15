import asyncio
import socket
from asyncio import StreamWriter, StreamReader
from logging import getLogger
from typing import Optional

from soxyproxy import Socks
from soxyproxy.protocols import Protocols
from soxyproxy.socks5 import (Socks5AuthMethods, Socks5HandshakeRequestMessage, Socks5HandshakeResponseMessage,
                              Socks5UsernameAuthResponseMessage, Socks5UsernameAuthRequestMessage,
                              Socks5ConnectionResponseMessage, Socks5ConnectionRequestMessage, Socks5ConnectionReplies)

logger = getLogger(__name__)


class Socks5(Socks):

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None) -> None:

        super().__init__(version=Protocols.SOCKS5)

        if username and not password or not username and password:
            raise KeyError

        self.username = username
        self.password = password
        self.auth_method = Socks5AuthMethods.USERNAME if username else Socks5AuthMethods.NO_AUTHENTICATION

    async def handshake(self, client_reader: StreamReader, client_writer: StreamWriter):

        request_raw = await client_reader.read(512)
        request = Socks5HandshakeRequestMessage.from_bytes(raw=request_raw)
        self._log_message(client_writer, message=request)

        auth = self.auth_method if self.auth_method in request.auth_methods else Socks5AuthMethods.NO_ACCEPTABLE

        response = Socks5HandshakeResponseMessage(auth_method=auth)
        self._log_message(client_writer, message=response)

        client_writer.write(response.as_bytes)

        if auth is Socks5AuthMethods.NO_ACCEPTABLE:
            raise ConnectionError(Socks5AuthMethods.NO_ACCEPTABLE.name)

    async def auth(self, client_reader: StreamReader,
                   client_writer: StreamWriter) -> Optional[Socks5UsernameAuthResponseMessage]:

        if self.auth_method is Socks5AuthMethods.NO_AUTHENTICATION:
            return

        if self.auth_method is Socks5AuthMethods.USERNAME:
            request_raw = await client_reader.read(128)
            request = Socks5UsernameAuthRequestMessage.from_bytes(request_raw)

            self._log_message(client_writer, request)

            auth_success = request.username == self.username and request.password == self.password
            response = Socks5UsernameAuthResponseMessage(status=auth_success)

            self._log_message(client_writer, response)

            if not auth_success:
                client_writer.write(response.as_bytes)
                raise ConnectionError('authorization failed')

            client_writer.write(response.as_bytes)

    async def connect(self, client_reader: StreamReader, client_writer: StreamWriter) -> (StreamReader, StreamWriter):

        request_raw = await client_reader.read(512)
        response: Optional[Socks5ConnectionResponseMessage] = None

        try:
            request = Socks5ConnectionRequestMessage.from_bytes(request_raw)
            self._log_message(client_writer, request)
            remote_reader, remote_writer = await asyncio.open_connection(host=str(request.address), port=request.port)
            response = Socks5ConnectionResponseMessage(reply=Socks5ConnectionReplies.SUCCEEDED,
                                                       address=request.address,
                                                       port=request.port)
            return remote_reader, remote_writer
        except socket.gaierror:
            response = Socks5ConnectionResponseMessage(
                reply=Socks5ConnectionReplies.HOST_UNREACHABLE,
                address=Socks5ConnectionRequestMessage.get_domain_name_from_raw(request_raw),
                port=Socks5ConnectionRequestMessage.get_port_from_raw(request_raw))
        except (OSError, TimeoutError):
            response = Socks5ConnectionResponseMessage(
                reply=Socks5ConnectionReplies.HOST_UNREACHABLE,
                address=Socks5ConnectionRequestMessage.get_address_from_raw(request_raw),
                port=Socks5ConnectionRequestMessage.get_port_from_raw(request_raw))
        finally:
            if response:
                self._log_message(client_writer, response)
                client_writer.write(response.as_bytes)

            if response and response.reply is not Socks5ConnectionReplies.SUCCEEDED:
                raise ConnectionError(response.reply.name)

    async def serve_client(self, client_reader: StreamReader, client_writer: StreamWriter):
        await self.handshake(client_reader=client_reader, client_writer=client_writer)
        await self.auth(client_reader=client_reader, client_writer=client_writer)
        await super().serve_client(client_reader=client_reader, client_writer=client_writer)
