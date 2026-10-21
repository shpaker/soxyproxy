import asyncio
import typing

import pytest

from soxy._session import Session


class FakeConnection:
    def __init__(
        self,
        name: str,
    ) -> None:
        self.name = name
        self.incoming: asyncio.Queue[bytes | BaseException] = asyncio.Queue()
        self.written = bytearray()
        self.eof_written = asyncio.Event()
        self.writable = asyncio.Event()
        self.writable.set()

    def __repr__(
        self,
    ) -> str:
        return f'<{self.name}>'

    def feed(
        self,
        *items: bytes | BaseException,
    ) -> None:
        for item in items:
            self.incoming.put_nowait(item)

    async def read(
        self,
    ) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, BaseException):
            raise item
        return item

    async def write(
        self,
        data: bytes,
    ) -> None:
        await self.writable.wait()
        self.written += data

    async def write_eof(
        self,
    ) -> None:
        self.eof_written.set()


async def wait_until(
    condition: typing.Callable[[], bool],
) -> None:
    async with asyncio.timeout(1):
        while not condition():  # noqa: ASYNC110
            await asyncio.sleep(0.001)


@pytest.fixture
def client() -> FakeConnection:
    return FakeConnection('client')


@pytest.fixture
def remote() -> FakeConnection:
    return FakeConnection('remote')


@pytest.mark.asyncio
async def test_session_relays_both_directions(client: FakeConnection, remote: FakeConnection) -> None:
    client.feed(b'hello', b' world', b'')
    remote.feed(b'response', b'')
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        await asyncio.wait_for(session.start(), timeout=1)
    assert remote.written == b'hello world'
    assert client.written == b'response'
    assert remote.eof_written.is_set()
    assert client.eof_written.is_set()
    assert session.sent == len(b'hello world')
    assert session.received == len(b'response')


@pytest.mark.asyncio
async def test_session_half_close(client: FakeConnection, remote: FakeConnection) -> None:
    client.feed(b'request', b'')
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        task = asyncio.create_task(session.start())
        await asyncio.wait_for(remote.eof_written.wait(), timeout=1)
        assert not task.done()
        remote.feed(b'response', b'')
        await asyncio.wait_for(task, timeout=1)
    assert remote.written == b'request'
    assert client.written == b'response'


@pytest.mark.asyncio
async def test_session_backpressure_does_not_block_other_direction(
    client: FakeConnection,
    remote: FakeConnection,
) -> None:
    remote.writable.clear()
    client.feed(b'upload')
    remote.feed(b'download')
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        task = asyncio.create_task(session.start())
        await wait_until(lambda: client.written == b'download')
        assert remote.written == b''
        remote.writable.set()
        await wait_until(lambda: remote.written == b'upload')
        client.feed(b'')
        remote.feed(b'')
        await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_session_connection_error_finishes_session(client: FakeConnection, remote: FakeConnection) -> None:
    remote.feed(ConnectionResetError())
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        await asyncio.wait_for(session.start(), timeout=1)


@pytest.mark.asyncio
async def test_session_unexpected_error_is_raised(client: FakeConnection, remote: FakeConnection) -> None:
    remote.feed(ValueError('boom'))
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        with pytest.raises(ExceptionGroup):
            await asyncio.wait_for(session.start(), timeout=1)


@pytest.mark.asyncio
async def test_session_cancellation_is_propagated(client: FakeConnection, remote: FakeConnection) -> None:
    async with Session(client=client, remote=remote) as session:  # type: ignore[arg-type]
        task = asyncio.create_task(session.start())
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
