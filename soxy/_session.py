import asyncio
import types
import typing
from traceback import print_exc

from soxy._logger import logger
from soxy._types import Connection


class Session:
    def __init__(
        self,
        client: Connection,
        remote: Connection,
    ) -> None:
        self._client = client
        self._remote = remote
        self._tasks: dict[Connection, asyncio.Task[bytes]] = {}
        self._finished: bool = True

    async def __aenter__(
        self,
    ) -> typing.Self:
        self._finished = False
        self._create_tasks()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: types.TracebackType | None,
    ) -> None:
        for task in self._tasks.values():
            if not task.cancelled():
                task.cancel()

    def _create_tasks(
        self,
    ) -> None:
        self._tasks = {
            self._client: asyncio.create_task(self._client.read()),
            self._remote: asyncio.create_task(self._remote.read()),
        }

    @property
    def connections(
        self,
    ) -> set[Connection]:
        return set(self._tasks.keys())

    async def _wait_tasks(self) -> None:
        try:
            done, _ = await asyncio.wait(
                self._tasks.values(),
                return_when=asyncio.FIRST_COMPLETED,
            )
        except TimeoutError:
            print_exc()
            self._finished = True
            return
        for conn, task in self._tasks.items():
            if task not in done:
                continue
            another: Connection = (self.connections - {conn}).pop()
            data = task.result()
            if not data:
                self._finished = True
                return
            self._tasks[conn] = asyncio.create_task(conn.read())
            await another.write(data)
            if conn is self._client:
                logger.info(f'{self._client} -> {len(data)} bytes -> {self._remote}')
            else:
                logger.info(f'{self._client} <- {len(data)} bytes <- {self._remote}')

    async def start(
        self,
    ) -> None:
        while self._finished is False:
            await self._wait_tasks()
