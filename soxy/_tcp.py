import asyncio
from collections.abc import Awaitable, Callable
from ipaddress import IPv4Address
from types import TracebackType
from typing import Self

from soxy._types import Address, Connection, Transport


class TCPConnection(
    Connection,
):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._reader = reader
        self._writer = writer
        address, port = self._writer.get_extra_info('peername')
        self._address = Address(
            ip=IPv4Address(address),
            port=port,
        )

    async def __aenter__(
        self,
    ) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: TracebackType | None,
    ) -> None:
        self._writer.close()
        await self._writer.wait_closed()

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
    ) -> Self:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

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


class TcpTransport(
    Transport,
):
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 1080,
    ) -> None:
        self._address = (host, port)
        self._on_client_connected_cb = None
        self._start_messaging_cb = None

    def init(
        self,
        on_client_connected_cb: Callable[
            [Connection],
            Awaitable[Address | None],
        ],
        start_messaging_cb: Callable[
            [Connection, Connection],
            Awaitable[None],
        ],
    ) -> None:
        self._on_client_connected_cb = on_client_connected_cb
        self._start_messaging_cb = start_messaging_cb

    async def __aenter__(
        self,
    ) -> asyncio.Server:
        return await asyncio.start_server(
            client_connected_cb=self._client_cb,
            host=self._address[0],
            port=self._address[1],
        )

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: TracebackType | None,
    ) -> None:
        pass

    async def _client_cb(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with TCPConnection(
            reader=reader,
            writer=writer,
        ) as client:
            if not (
                destination := await self._on_client_connected_cb(
                    client=client,
                )
            ):
                return
            async with await TCPConnection.open(
                host=str(destination.ip),
                port=destination.port,
            ) as remote:
                await self._start_messaging_cb(
                    client=client,
                    remote=remote,
                )
