import asyncio
from abc import abstractmethod, ABC
from asyncio import StreamWriter, StreamReader, Task, create_task, FIRST_COMPLETED
from dataclasses import asdict
from logging import getLogger
from typing import Optional

from soxyproxy.protocols import Protocols
from soxyproxy.socks import RequestMessage

READ_BYTES_DEFAULT = 1024

logger = getLogger(__name__)


class Socks(ABC):

    def __init__(self, version: Protocols):
        self.version = version
        logger.info(f'Serve {self.version.name}')

    async def server_connection_callback(self, client_reader: StreamReader, client_writer: StreamWriter) -> None:

        host, port = client_writer.get_extra_info('peername')

        try:
            await self.serve_client(client_reader=client_reader, client_writer=client_writer)
        except ValueError as err:
            logger.warning(f'{host}:{port} package error: {err}')
        except ConnectionError as err:
            logger.warning(f'{host}:{port} connection error: {err}')
        finally:
            if not client_writer.is_closing():
                await client_writer.drain()

            client_writer.close()
            logger.info(f'{host}:{port} close session')

    async def run(self, host: str, port: int) -> None:
        server = await asyncio.start_server(client_connected_cb=self.server_connection_callback, host=host, port=port)

        async with server:
            await server.serve_forever()

    @abstractmethod
    async def connect(self, client_reader: StreamReader, client_writer: StreamWriter) -> (StreamReader, StreamWriter):
        raise NotImplementedError

    async def serve_client(self, client_reader: StreamReader, client_writer: StreamWriter):

        client_host, client_port = client_writer.get_extra_info('peername')

        try:
            remote_reader, remote_writer = await self.connect(client_reader=client_reader, client_writer=client_writer)
            remote_host, remote_port = remote_writer.get_extra_info('peername')
            logger.info(f'{client_host}:{client_port} <-> {remote_host}:{remote_port} start interaction')

            await self.proxy(client_reader=client_reader,
                             client_writer=client_writer,
                             remote_reader=remote_reader,
                             remote_writer=remote_writer)
        except ConnectionResetError as err:
            logger.error(err)

    async def proxy(self, client_reader: StreamReader, client_writer: StreamWriter, remote_reader: StreamReader,
                    remote_writer: StreamWriter):

        client_read_task = create_task(client_reader.read(READ_BYTES_DEFAULT))
        remote_read_task = create_task(remote_reader.read(READ_BYTES_DEFAULT))

        while client_read_task and remote_read_task:

            done, pending = await asyncio.wait({client_read_task, remote_read_task}, return_when=FIRST_COMPLETED)

            if client_read_task in done:
                client_read_task = await self._proxy_connection(in_read=client_read_task,
                                                                out_read=remote_read_task,
                                                                in_reader=client_reader,
                                                                out_writer=remote_writer)

            if remote_read_task in done:
                remote_read_task = await self._proxy_connection(in_read=remote_read_task,
                                                                out_read=client_read_task,
                                                                in_reader=remote_reader,
                                                                out_writer=client_writer)

        if client_read_task:
            client_read_task.cancel()

        if remote_read_task:
            remote_read_task.cancel()

        remote_writer.close()

    async def _proxy_connection(self, in_read: Task, out_read: Task, in_reader: StreamReader,
                                out_writer: StreamWriter) -> Optional[asyncio.Task]:

        data: bytes = in_read.result()

        if not data:
            out_read.cancel()
            return

        out_writer.write(data)
        await out_writer.drain()

        return asyncio.create_task(in_reader.read(512))

    def _log_message(self, writer, message, is_debug=False):
        host, port = writer.get_extra_info('peername')
        arrow = '->' if isinstance(message, RequestMessage) else '<-'
        output = f'{host}:{port} {arrow} {asdict(message)}'
        logger.debug(output) if is_debug else logger.info(output)
