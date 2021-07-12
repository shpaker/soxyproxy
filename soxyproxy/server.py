from abc import ABC, abstractmethod
from asyncio import FIRST_COMPLETED, StreamReader, StreamWriter, create_task, start_server, wait
from logging import getLogger
from typing import Any, Tuple

from soxyproxy.connections import SocksConnection
from soxyproxy.exceptions import SocksError
from soxyproxy.internal.ruleset import raise_for_connection_ruleset
from soxyproxy.models.ruleset import RuleSet

READ_BYTES_DEFAULT = 512
logger = getLogger(__name__)


class ServerBase(ABC):
    def __init__(
        self,
        ruleset: RuleSet = RuleSet(),
    ) -> None:
        self.ruleset: RuleSet = ruleset

    async def _client_connected_cb(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> None:
        client = SocksConnection(reader=client_reader, writer=client_writer)
        try:
            raise_for_connection_ruleset(ruleset=self.ruleset, client=client)
            await self._start_interaction(client=client)
        except SocksError:
            pass

        if not client.writer.is_closing():
            await client.writer.drain()
        client.writer.close()
        logger.info(f"{client} close session")

    async def serve(
        self,
        host: str,
        port: int,
    ) -> None:
        logger.info(f"Start {self.__class__.__name__.lower()} server {host}:{port}")
        server = await start_server(client_connected_cb=self._client_connected_cb, host=host, port=port)
        async with server:
            await server.serve_forever()

    @abstractmethod
    async def proxy_connect(
        self,
        client: SocksConnection,
        **kwargs: Any,
    ) -> Tuple[StreamReader, StreamWriter]:
        raise NotImplementedError

    async def _start_interaction(
        self,
        client: SocksConnection,
        **kwargs: Any,
    ) -> None:
        remote_reader, remote_writer = await self.proxy_connect(client=client, **kwargs)
        remote = SocksConnection(remote_reader, remote_writer)
        logger.info(f"{client} <-> {remote} start interaction")

        client_read_task = create_task(client.reader.read(READ_BYTES_DEFAULT))
        remote_read_task = create_task(remote.reader.read(READ_BYTES_DEFAULT))

        while client_read_task is not None and remote_read_task is not None:

            done, _ = await wait({client_read_task, remote_read_task}, return_when=FIRST_COMPLETED)

            if client_read_task in done:
                client_read_task = await self._proxy_connection(
                    in_read=client_read_task,
                    out_read=remote_read_task,
                    in_reader=client.reader,
                    out_writer=remote.writer,
                )

            if remote_read_task in done:
                remote_read_task = await self._proxy_connection(
                    in_read=remote_read_task,
                    out_read=client_read_task,
                    in_reader=remote.reader,
                    out_writer=client.writer,
                )

        if client_read_task:
            client_read_task.cancel()

        if remote_read_task:
            remote_read_task.cancel()

        remote.writer.close()

    @staticmethod
    async def _proxy_connection(  # type: ignore
        in_read,
        out_read,
        in_reader: StreamReader,
        out_writer: StreamWriter,
    ):
        data: bytes = in_read.result()
        if not data:
            out_read.cancel()
            return None
        out_writer.write(data)
        await out_writer.drain()
        return create_task(in_reader.read(READ_BYTES_DEFAULT))
