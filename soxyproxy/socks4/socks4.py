from asyncio import StreamReader, StreamWriter, open_connection
from typing import Optional

from soxyproxy import Socks
from soxyproxy.protocols import Protocols
from soxyproxy.socks4 import Socks4ConnectionResponseMessage, Socks4ConnectionRequestMessage, Socks4Replies


class Socks4(Socks):

    def __init__(self) -> None:
        super().__init__(Protocols.SOCKS4)

    async def connect(self, client_reader: StreamReader, client_writer: StreamWriter) -> (StreamReader, StreamWriter):

        request_raw = await client_reader.read(512)
        response: Optional[Socks4ConnectionResponseMessage] = None

        try:
            request = Socks4ConnectionRequestMessage.from_bytes(request_raw)
            self._log_message(client_writer, request)
            remote_reader, remote_writer = await open_connection(host=str(request.address), port=request.port)
            response = Socks4ConnectionResponseMessage(reply=Socks4Replies.GRANTED,
                                                       address=request.address,
                                                       port=request.port)
            return remote_reader, remote_writer
        except (OSError, TimeoutError):
            response = Socks4ConnectionResponseMessage(
                reply=Socks4Replies.REJECTED,
                address=Socks4ConnectionRequestMessage.get_address_from_raw(request_raw),
                port=Socks4ConnectionRequestMessage.get_port_from_raw(request_raw))
        finally:
            if response:
                self._log_message(client_writer, response)
                client_writer.write(response.as_bytes)

            if response and response.reply is not Socks4Replies.GRANTED:
                raise ConnectionError(response.reply.name)
