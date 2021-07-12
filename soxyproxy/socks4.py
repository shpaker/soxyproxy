import logging
from asyncio import StreamReader, StreamWriter, open_connection
from typing import Optional, Tuple

from soxyproxy.connections import SocksConnection
from soxyproxy.consts import Socks4Reply
from soxyproxy.exceptions import SocksConnectionError
from soxyproxy.internal.socks4 import socks4_raise_for_proxy_ruleset
from soxyproxy.models.socks4 import connection
from soxyproxy.server import ServerBase

logger = logging.getLogger(__name__)


class Socks4(ServerBase):
    async def proxy_connect(  # type: ignore
        self,
        client: SocksConnection,
        **kwargs,
    ) -> Optional[Tuple[StreamReader, StreamWriter]]:

        request_raw = await client.reader.read(512)
        request = connection.RequestModel.load(client=client, raw=request_raw)
        logger.debug(f"{client} -> {request.json()}")

        socks4_raise_for_proxy_ruleset(client=client, ruleset=self.ruleset, request=request)

        remote_reader, remote_writer = await self._open_remote_connection(client=client, request=request)
        response = connection.ResponseModel(
            reply=Socks4Reply.GRANTED,
            address=request.address,
            port=request.port,
        )
        client.writer.write(response.dump())
        logger.warning(f"{client} <- {request.json()}")

        return remote_reader, remote_writer

    @staticmethod
    async def _open_remote_connection(
        client: SocksConnection,
        request: connection.RequestModel,
    ) -> Tuple[StreamReader, StreamWriter]:
        try:
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
        except ConnectionError as err:
            response = connection.ResponseModel(
                reply=Socks4Reply.REJECTED,
                address=request.address,
                port=request.port,
            )
            client.writer.write(response.dump())
            logger.warning(f"{client} <- {request.json()}")
            raise SocksConnectionError(
                client=client,
                host=str(request.address),
                port=request.port,
            ) from err
        return remote_reader, remote_writer
