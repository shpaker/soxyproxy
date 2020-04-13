import asyncio
import socket
from asyncio import StreamWriter, StreamReader
from logging import getLogger
from typing import Optional

from . import (HandshakeRequest, HandshakeResponse, UsernameAuthRequest, UsernameAuthResponse)
from .codes import ReplyCodes, AuthMethods
from .messages.connection.connection_request import ConnectionRequest
from .messages.connection.connection_response import ConnectionResponse
from ..socks import Socks
from ..socks_versions import SocksVersions

logger = getLogger(__name__)


class Socks5(Socks):

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None) -> None:

        super().__init__(version=SocksVersions.SOCKS5)

        self.username = username
        self.password = password
        self.auth_method: AuthMethods = AuthMethods.USERNAME if username else AuthMethods.NO_AUTHENTICATION

    async def handshake(self, client_reader: StreamReader, client_writer: StreamWriter):

        request_raw = await client_reader.read(512)
        request = HandshakeRequest.from_bytes(raw=request_raw)
        self._log_message(client_writer, message=request)

        if self.auth_method not in request.auth_methods:
            raise ConnectionError(f'denied authorization methods {request.auth_methods}')

        response = HandshakeResponse(self.auth_method)

        self._log_message(client_writer, message=response)
        client_writer.write(response.as_bytes)

    async def auth(self, client_reader: StreamReader, client_writer: StreamWriter) -> Optional[UsernameAuthResponse]:

        if self.auth_method is AuthMethods.NO_AUTHENTICATION:
            return

        if self.auth_method is AuthMethods.USERNAME:
            request_raw = await client_reader.read(128)
            request = UsernameAuthRequest.from_bytes(request_raw)

            self._log_message(client_writer, request)

            auth_success = request.username == self.username and request.password == self.password
            response = UsernameAuthResponse(status=auth_success)

            self._log_message(client_writer, response)

            if not auth_success:
                client_writer.write(response.as_bytes)
                raise ConnectionError('authorization failed')

            client_writer.write(response.as_bytes)

    async def connect(self, client_reader: StreamReader, client_writer: StreamWriter) -> (StreamReader, StreamWriter):

        request_raw = await client_reader.read(512)
        response: Optional[ConnectionResponse] = None

        try:
            request = ConnectionRequest.from_bytes(request_raw)
            self._log_message(client_writer, request)
            remote_reader, remote_writer = await asyncio.open_connection(host=str(request.address), port=request.port)
            response = ConnectionResponse(reply=ReplyCodes.SUCCEEDED, address=request.address, port=request.port)
            return remote_reader, remote_writer
        except socket.gaierror:
            response = ConnectionResponse(reply=ReplyCodes.HOST_UNREACHABLE,
                                          address=ConnectionRequest.get_domain_name_from_raw(request_raw),
                                          port=ConnectionRequest.get_port_from_raw(request_raw))
        except (OSError, TimeoutError):
            response = ConnectionResponse(reply=ReplyCodes.HOST_UNREACHABLE,
                                          address=ConnectionRequest.get_address_from_raw(request_raw),
                                          port=ConnectionRequest.get_port_from_raw(request_raw))
        finally:
            if response:
                self._log_message(client_writer, response)
                client_writer.write(response.as_bytes)

            if response and response.reply is not ReplyCodes.SUCCEEDED:
                raise ConnectionError(response.reply.name)

    async def serve_client(self, client_reader: StreamReader, client_writer: StreamWriter):
        await self.handshake(client_reader=client_reader, client_writer=client_writer)
        await self.auth(client_reader=client_reader, client_writer=client_writer)
        await super().serve_client(client_reader=client_reader, client_writer=client_writer)
