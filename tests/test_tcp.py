import asyncio
from ipaddress import IPv4Address

import pytest

from soxy._tcp import TCPConnection, TcpTransport
from soxy._types import Address, Connection


@pytest.mark.asyncio
async def test_tcp_connection_read_write() -> None:
    async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data: bytes = await reader.read(1024)
        writer.write(data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server: asyncio.Server = await asyncio.start_server(echo_handler, '127.0.0.1', 0)
    addr: tuple[str, int] = server.sockets[0].getsockname()

    try:
        async with await TCPConnection.open('127.0.0.1', addr[1]) as conn:
            test_data: bytes = b'Hello, World!'
            await conn.write(test_data)
            response: bytes = await conn.read()
            assert response == test_data
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_connection_context_manager() -> None:
    writer_closed: bool = False

    class MockWriter:
        async def wait_closed(self) -> None:
            nonlocal writer_closed
            writer_closed = True

        def close(self) -> None:
            pass

        def get_extra_info(self, *args: str) -> tuple[str, int]:
            return '127.0.0.1', 12345

    conn: TCPConnection = TCPConnection(asyncio.StreamReader(), MockWriter())
    async with conn:
        pass
    assert writer_closed


@pytest.mark.asyncio
async def test_tcp_transport_flow() -> None:
    connected_clients: list[Connection] = []

    async def on_client_connected(conn: Connection) -> Address:
        connected_clients.append(conn)
        return Address(ip=IPv4Address('127.0.0.1'), port=12345)

    async def start_messaging(client: Connection, remote: Connection) -> None:
        pass

    async def on_remote_unreachable(client: Connection, addr: Address) -> None:
        pass

    transport: TcpTransport = TcpTransport(port=0)
    transport.init(on_client_connected, start_messaging, on_remote_unreachable)

    async with transport as server:
        addr: tuple[str, int] = server.sockets[0].getsockname()
        async with await TCPConnection.open('127.0.0.1', addr[1]):
            await asyncio.sleep(0.1)
            assert len(connected_clients) == 1


@pytest.mark.asyncio
async def test_tcp_connection_error() -> None:
    try:
        async with asyncio.timeout(1):
            with pytest.raises(OSError):
                await TCPConnection.open('127.0.0.1', 65535)
    except TimeoutError:
        pytest.fail('Connection attempt timed out')
