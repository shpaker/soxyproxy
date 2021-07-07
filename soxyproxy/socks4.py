import logging
from asyncio import StreamReader, StreamWriter, open_connection
from typing import Optional, Tuple

from soxyproxy.consts import Socks4Reply
from soxyproxy.models.socks4 import connection
from soxyproxy.server import ServerBase

logger = logging.getLogger(__name__)


class Socks4(ServerBase):
    async def connect(  # type: ignore
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> Optional[Tuple[StreamReader, StreamWriter]]:
        request_raw = await client_reader.read(512)
        host, port = client_writer.get_extra_info("peername")
        try:
            request = connection.RequestModel.loads(request_raw)
            logger.debug(f"{host}:{port} -> {request.json()}")
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
        except (ConnectionError, TimeoutError) as err:
            response = connection.ResponseModel(
                reply=Socks4Reply.REJECTED,
                address=connection.extract_address(request_raw),
                port=connection.extract_port(request_raw),
            )
            client_writer.write(response.dumps())
            raise ConnectionError(err) from err
        except Exception as err:
            raise ValueError(err) from err
        response = connection.ResponseModel(
            reply=Socks4Reply.GRANTED,
            address=request.address,
            port=request.port,
        )
        client_writer.write(response.dumps())
        return remote_reader, remote_writer
