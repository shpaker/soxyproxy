import asyncio
import types
import typing
from ipaddress import IPv4Address

from soxy._session import Session
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
    ) -> typing.Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: types.TracebackType | None,
    ) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except ConnectionError:
            return

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
    ) -> typing.Self:
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
        self._on_client_connected_cb: typing.Callable[[Connection], typing.Awaitable[Address | None]] | None = None
        self._start_messaging_cb: typing.Callable[[Connection, Connection], typing.Awaitable[None]] | None = None
        self._on_remote_unreachable_cb: typing.Callable[[Connection, Address], typing.Awaitable[None]] | None = None

    def init(
        self,
        on_client_connected_cb: typing.Callable[
            [Connection],
            typing.Awaitable[Address | None],
        ],
        start_messaging_cb: typing.Callable[
            [Connection, Connection],
            typing.Awaitable[None],
        ],
        on_remote_unreachable_cb: typing.Callable[
            [Connection, Address],
            typing.Awaitable[None],
        ],
    ) -> None:
        self._on_client_connected_cb = on_client_connected_cb
        self._start_messaging_cb = start_messaging_cb
        self._on_remote_unreachable_cb = on_remote_unreachable_cb

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
        exc_traceback: types.TracebackType | None,
    ) -> None:
        pass

    async def _client_cb(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if (
            self._on_client_connected_cb is None
            or self._start_messaging_cb is None
            or self._on_remote_unreachable_cb is None
        ):
            msg = f'please initialize {self.__class__.__name__}'
            raise RuntimeError(msg)
        async with TCPConnection(
            reader=reader,
            writer=writer,
        ) as client:
            if not (destination := await self._on_client_connected_cb(client)):
                return
            try:
                async with await TCPConnection.open(
                    host=str(destination.ip),
                    port=destination.port,
                ) as remote:
                    await self._start_messaging_cb(client, remote)
                    async with Session(
                        client=client,
                        remote=remote,
                    ) as session:
                        await session.start()
            except OSError:
                await self._on_remote_unreachable_cb(client, destination)
                return
