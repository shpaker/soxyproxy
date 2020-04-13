from asyncio import StreamReader, StreamWriter, open_connection
from typing import Optional

from . import ConnectionRequest, ConnectionResponse, ReplyCodes
from .. import Socks
from ..socks_versions import SocksVersions


class Socks4(Socks):

    def __init__(self) -> None:
        super().__init__(SocksVersions.SOCKS4)

    async def connect(self, client_reader: StreamReader, client_writer: StreamWriter) -> (StreamReader, StreamWriter):

        request_raw = await client_reader.read(512)
        response: Optional[ConnectionResponse] = None

        try:
            request = ConnectionRequest.from_bytes(request_raw)
            self._log_message(client_writer, request)
            remote_reader, remote_writer = await open_connection(host=str(request.address), port=request.port)
            response = ConnectionResponse(reply=ReplyCodes.GRANTED, address=request.address, port=request.port)
            return remote_reader, remote_writer
        except (OSError, TimeoutError):
            response = ConnectionResponse(reply=ReplyCodes.REJECTED,
                                          address=ConnectionRequest.get_address_from_raw(request_raw),
                                          port=ConnectionRequest.get_port_from_raw(request_raw))
        finally:
            if response:
                self._log_message(client_writer, response)
                client_writer.write(response.as_bytes)

            if response and response.reply is not ReplyCodes.GRANTED:
                raise ConnectionError(response.reply.name)
