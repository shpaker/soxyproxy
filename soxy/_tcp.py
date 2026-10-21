import asyncio
import types
import typing
from ipaddress import IPv4Address

from soxy._logger import logger
from soxy._session import Session
from soxy._types import (
    Address,
    Connection,
    OnClientConnectedCallback,
    OnRemoteUnreachableCallback,
    StartMessagingCallback,
    Transport,
)
from soxy._utils import address_from_sockaddr

_READ_CHUNK_SIZE = 64 * 1024
_CLOSE_TIMEOUT = 5.0


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
        self._address = address_from_sockaddr(peername)
        sockname = self._writer.get_extra_info('sockname')
        self._local_address = address_from_sockaddr(sockname) if sockname else Address(ip=IPv4Address(0), port=0)

    @property
    def local_address(
        self,
    ) -> Address:
        return self._local_address

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
        await self.close()

    async def close(
        self,
    ) -> None:
        self._writer.close()
        try:
            async with asyncio.timeout(_CLOSE_TIMEOUT):
                await self._writer.wait_closed()
        except TimeoutError:
            # peer does not read, so buffered data can't be flushed
            self._writer.transport.abort()
        except OSError:
            return
        except asyncio.CancelledError:
            self._writer.transport.abort()
            raise

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
    ) -> typing.Self:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            return cls(reader, writer)
        except Exception:
            writer.transport.abort()
            raise

    async def read(
        self,
    ) -> bytes:
        return await self._reader.read(_READ_CHUNK_SIZE)

    async def readexactly(
        self,
        n: int,
    ) -> bytes:
        return await self._reader.readexactly(n)

    async def readuntil(
        self,
        separator: bytes,
    ) -> bytes:
        return await self._reader.readuntil(separator)

    async def write(
        self,
        data: bytes,
    ) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def write_eof(
        self,
    ) -> None:
        if self._writer.is_closing() or not self._writer.can_write_eof():
            return
        self._writer.write_eof()


class TcpTransport(
    Transport,
):
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 1080,
        handshake_timeout: float = 30,
        connect_timeout: float = 10,
        shutdown_timeout: float = 5,
    ) -> None:
        self._address = (host, port)
        self._handshake_timeout = handshake_timeout
        self._connect_timeout = connect_timeout
        self._shutdown_timeout = shutdown_timeout
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._on_client_connected_cb: OnClientConnectedCallback | None = None
        self._start_messaging_cb: StartMessagingCallback | None = None
        self._on_remote_unreachable_cb: OnRemoteUnreachableCallback | None = None

    def init(
        self,
        on_client_connected_cb: OnClientConnectedCallback,
        start_messaging_cb: StartMessagingCallback,
        on_remote_unreachable_cb: OnRemoteUnreachableCallback,
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
        if self._server is None:
            return
        server, self._server = self._server, None
        server.close()
        if handlers := set(self._handlers):
            for handler in handlers:
                handler.cancel()
            await asyncio.wait(handlers, timeout=self._shutdown_timeout)
        server.close_clients()
        try:
            async with asyncio.timeout(self._shutdown_timeout):
                await server.wait_closed()
        except TimeoutError:
            server.abort_clients()
            await server.wait_closed()

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
        if (task := asyncio.current_task()) is not None:
            self._handlers.add(task)
        try:
            try:
                client = TCPConnection(
                    reader=reader,
                    writer=writer,
                )
            except RuntimeError:
                # client has gone before we've got its address
                writer.transport.abort()
                return
            async with client:
                if (destination := await self._handshake(client, self._on_client_connected_cb)) is None:
                    return
                if (remote := await self._connect(client, destination, self._on_remote_unreachable_cb)) is None:
                    return
                async with remote:
                    await self._relay(client, remote, self._start_messaging_cb)
        finally:
            if task is not None:
                self._handlers.discard(task)

    async def _handshake(
        self,
        client: Connection,
        on_client_connected_cb: OnClientConnectedCallback,
    ) -> Address | None:
        try:
            async with asyncio.timeout(self._handshake_timeout):
                destination = await on_client_connected_cb(client)
        except TimeoutError:
            logger.info(f'{client} handshake timeout')
            return None
        except OSError as exc:
            logger.info(f'{client} connection lost during handshake ({exc!r})')
            return None
        except Exception:  # noqa: BLE001
            logger.exception('Error in on_client_connected_cb')
            return None
        return destination

    async def _connect(
        self,
        client: Connection,
        destination: Address,
        on_remote_unreachable_cb: OnRemoteUnreachableCallback,
    ) -> TCPConnection | None:
        try:
            async with asyncio.timeout(self._connect_timeout):
                remote = await TCPConnection.open(
                    host=str(destination.ip),
                    port=destination.port,
                )
        except OSError as exc:
            try:
                await on_remote_unreachable_cb(client, destination, exc)
            except OSError:
                pass
            except Exception:  # noqa: BLE001
                logger.exception('Error in on_remote_unreachable_cb')
            return None
        return remote

    async def _relay(
        self,
        client: Connection,
        remote: Connection,
        start_messaging_cb: StartMessagingCallback,
    ) -> None:
        try:
            await start_messaging_cb(client, remote)
        except OSError as exc:
            logger.info(f'{client} connection lost before relaying ({exc!r})')
            return
        except Exception:  # noqa: BLE001
            logger.exception('Error in start_messaging_cb')
            return
        try:
            async with Session(
                client=client,
                remote=remote,
            ) as session:
                await session.start()
        except Exception:  # noqa: BLE001
            logger.exception('Session error')
