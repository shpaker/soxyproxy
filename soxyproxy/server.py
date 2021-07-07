from abc import ABC, abstractmethod
from asyncio import (
    FIRST_COMPLETED,
    StreamReader,
    StreamWriter,
    Task,
    create_task,
    start_server,
    wait,
)
from logging import getLogger
from typing import Optional, Tuple

READ_BYTES_DEFAULT = 1024
logger = getLogger(__name__)


class ServerBase(ABC):
    async def server_connection_callback(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> None:
        host, port = client_writer.get_extra_info("peername")
        try:
            await self.serve_client(
                client_reader=client_reader,
                client_writer=client_writer,
            )
        except ValueError as err:
            logger.warning(f"{host}:{port} ! package error: {err}")
        except ConnectionError as err:
            logger.warning(f"{host}:{port} ! connection error: {err}")
        finally:
            if not client_writer.is_closing():
                await client_writer.drain()
            client_writer.close()
            logger.info(f"{host}:{port} close session")

    async def run(
        self,
        host: str,
        port: int,
    ) -> None:
        logger.info(f"Start {self.__class__.__name__.lower()} server {host}:{port}")
        server = await start_server(
            client_connected_cb=self.server_connection_callback, host=host, port=port
        )
        async with server:
            await server.serve_forever()

    @abstractmethod
    async def connect(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> Tuple[StreamReader, StreamWriter]:
        raise NotImplementedError

    async def serve_client(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
    ) -> None:
        client_host, client_port = client_writer.get_extra_info("peername")

        remote_reader, remote_writer = await self.connect(
            client_reader=client_reader,
            client_writer=client_writer,
        )
        remote_host, remote_port = remote_writer.get_extra_info("peername")
        logger.info(
            f"{client_host}:{client_port} <-> {remote_host}:{remote_port} session"
        )
        await self.proxy(
            client_reader=client_reader,
            client_writer=client_writer,
            remote_reader=remote_reader,
            remote_writer=remote_writer,
        )

    async def proxy(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        remote_reader: StreamReader,
        remote_writer: StreamWriter,
    ) -> None:

        client_read_task = create_task(client_reader.read(READ_BYTES_DEFAULT))
        remote_read_task = create_task(remote_reader.read(READ_BYTES_DEFAULT))

        while client_read_task is not None and remote_read_task is not None:

            done, _ = await wait(
                {client_read_task, remote_read_task}, return_when=FIRST_COMPLETED
            )

            if client_read_task in done:
                client_read_task = await self._proxy_connection(  # type: ignore
                    in_read=client_read_task,
                    out_read=remote_read_task,
                    in_reader=client_reader,
                    out_writer=remote_writer,
                )

            if remote_read_task in done:
                remote_read_task = await self._proxy_connection(  # type: ignore
                    in_read=remote_read_task,
                    out_read=client_read_task,
                    in_reader=remote_reader,
                    out_writer=client_writer,
                )

        if client_read_task:
            client_read_task.cancel()

        if remote_read_task:
            remote_read_task.cancel()

        remote_writer.close()

    async def _proxy_connection(
        self,
        in_read: Task,  # type: ignore
        out_read: Task,  # type: ignore
        in_reader: StreamReader,
        out_writer: StreamWriter,
    ) -> Optional[Task]:  # type: ignore
        data: bytes = in_read.result()
        if not data:
            out_read.cancel()
            return None
        out_writer.write(data)
        await out_writer.drain()
        return create_task(in_reader.read(512))
