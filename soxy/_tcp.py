import asyncio
import types
import typing
from ipaddress import IPv4Address, IPv6Address

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
        peername = self._writer.get_extra_info('peername')
        if peername is None:
            msg = 'peername is not available'
            raise RuntimeError(msg)
        address, port = peername
        try:
            ip = IPv4Address(address)
        except ValueError:
            ip = IPv6Address(address)
        self._address = Address(
            ip=ip,
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
        self._server: asyncio.Server | None = None
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
        self._server = await asyncio.start_server(
            client_connected_cb=self._client_cb,
            host=self._address[0],
            port=self._address[1],
        )
        return self._server

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: types.TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

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
            try:
                if not (destination := await self._on_client_connected_cb(client)):
                    return
            except Exception as exc:
                logger.exception(f'Error in on_client_connected_cb: {exc}')
                return
            try:
                async with await TCPConnection.open(
                    host=str(destination.ip),
                    port=destination.port,
                ) as remote:
                    try:
                        await self._start_messaging_cb(client, remote)
                    except Exception as exc:
                        logger.exception(f'Error in start_messaging_cb: {exc}')
                        return
                    try:
                        async with Session(
                            client=client,
                            remote=remote,
                        ) as session:
                            await session.start()
                    except Exception as exc:
                        logger.exception(f'Session error: {exc}')
            except OSError:
                try:
                    await self._on_remote_unreachable_cb(client, destination)
                except Exception as exc:
                    logger.exception(f'Error in on_remote_unreachable_cb: {exc}')
                return
            except Exception as exc:
                logger.exception(f'Connection error: {exc}')
                return
