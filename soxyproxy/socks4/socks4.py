from asyncio import StreamReader, StreamWriter, open_connection
from dataclasses import asdict

from noSocks.socks.exceptions import SocksConnectionError
from noSocks.socks.connection_data import ConnectionData
from noSocks.socks4.codes import ReplyCodes
from noSocks.socks4 import request_from_bytes
from noSocks.socks4 import Response
from noSocks.socks.socks_abstract import SocksAbstract


class Socks4(SocksAbstract):

    def __init__(self, client_reader: StreamReader, client_writer: StreamWriter) -> None:
        super().__init__(client_reader, client_writer)

    async def connect(self):

        data = await self.client.reader.read(512)
        request = request_from_bytes(data)

        self.logger.info(
            f'{self.client} -> SOCKS{request.socks_version.name} request to {request.remote_address}:{request.remote_port}'
        )

        try:
            _remote_reader, _remote_writer = await open_connection(host=str(request.remote_address),
                                                                   port=request.remote_port)
        except (OSError, TimeoutError):
            response = Response(reply_code=ReplyCodes.rejected,
                                destination_address=request.remote_address,
                                destination_port=request.remote_port)

            raise SocksConnectionError(response=response.as_bytes)

        self.remote = ConnectionData(reader=_remote_reader, writer=_remote_writer)

        response = Response(reply_code=ReplyCodes.granted,
                            destination_address=request.remote_address,
                            destination_port=request.remote_port)

        self.logger.info(f'{self.client} <- {asdict(response)}')

        self.client.writer.write(response.as_bytes)
