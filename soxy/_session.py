import asyncio
import types
import typing

from soxy._logger import logger
from soxy._types import Connection


class Session:
    """
    Bidirectional relay between client and remote connections.

    Each direction is pumped independently, so backpressure in one direction
    doesn't stall the other. EOF from one side is propagated to the other side
    as half-close; the session finishes when both directions are closed or
    when any of connections fails.
    """

    def __init__(
        self,
        client: Connection,
        remote: Connection,
    ) -> None:
        self._client = client
        self._remote = remote
        self._sent = 0
        self._received = 0

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
        logger.info(f'{self._client} session closed (sent {self._sent} bytes, received {self._received} bytes)')

    @property
    def sent(
        self,
    ) -> int:
        return self._sent

    @property
    def received(
        self,
    ) -> int:
        return self._received

    async def start(
        self,
    ) -> None:
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._pump(self._client, self._remote))
                tg.create_task(self._pump(self._remote, self._client))
        except* OSError as group:
            logger.info(f'{self._client} session interrupted ({group.exceptions[0]!r})')

    async def _pump(
        self,
        source: Connection,
        destination: Connection,
    ) -> None:
        while data := await source.read():
            await destination.write(data)
            if source is self._client:
                self._sent += len(data)
                logger.debug(f'{self._client} -> {len(data)} bytes -> {self._remote}')
            else:
                self._received += len(data)
                logger.debug(f'{self._client} <- {len(data)} bytes <- {self._remote}')
        await destination.write_eof()
