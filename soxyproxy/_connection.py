import asyncio
from typing import Self

from soxyproxy._logger import logger
from soxyproxy._types import Status


class TCPConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.status = Status.CLIENT

    def __repr__(self) -> str:
        host, port = self._writer.get_extra_info('peername')
        return f'<Connection|{self.status.name} {host}:{port}>'

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._writer.close()
        await self._writer.wait_closed()
        logger.info(f'{self} close')

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
    ) -> Self:
        reader, writer = await asyncio.open_connection(host, port)
        conn = cls(reader, writer)
        conn.status = Status.REMOTE
        logger.info(f'{conn} open')
        return conn

    async def read(
        self,
    ) -> bytes:
        return await self._reader.read(n=1024)

    async def write(
        self,
        data: bytes,
    ) -> None:
        self._writer.write(data)
        await self._writer.drain()
