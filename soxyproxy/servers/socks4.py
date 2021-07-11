import logging
from asyncio import StreamReader, StreamWriter
from typing import Optional, Tuple

from soxyproxy.consts import Socks4Reply
from soxyproxy.internal.socks4 import check_ruleset, open_remote_connection
from soxyproxy.models.client import ClientModel
from soxyproxy.models.socks4 import connection
from soxyproxy.servers.base import ServerBase

logger = logging.getLogger(__name__)


class Socks4(ServerBase):
    async def connect(  # type: ignore
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        **kwargs,
    ) -> Optional[Tuple[StreamReader, StreamWriter]]:
        client = ClientModel.from_writer(client_writer)
        request_raw = await client_reader.read(512)
        request = connection.RequestModel.loads(
            client=client,
            raw=request_raw,
        )
        logger.debug(f"{client} -> {request.json()}")
        check_ruleset(
            client=client,
            client_writer=client_writer,
            ruleset=self.ruleset,
            request=request,
        )
        remote_reader, remote_writer = await open_remote_connection(
            client=client,
            client_writer=client_writer,
            request=request,
        )
        response = connection.ResponseModel(
            reply=Socks4Reply.GRANTED,
            address=request.address,
            port=request.port,
        )
        client_writer.write(response.dumps())
        logger.warning(f"{client} <- {request.json()}")
        return remote_reader, remote_writer
