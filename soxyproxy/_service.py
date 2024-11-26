import asyncio
from datetime import datetime
from traceback import print_exc

from soxyproxy._errors import (
    SocksIncorrectVersionError,
    SocksPackageError,
    SocksRejectError,
)
from soxyproxy._logger import logger
from soxyproxy._types import Connection, Destination, ProxySocks, Status


class ProxyService:
    def __init__(
        self,
        protocol: ProxySocks,
    ) -> None:
        self._protocol = protocol

    async def on_target_open(
        self,
        client: Connection,
        dest: Destination,
    ):
        await self._protocol.success(
            client=client,
            destination=dest,
        )

    async def on_target_unreachable(
        self,
        client: Connection,
        dest: Destination,
    ):
        await self._protocol.target_unreachable(
            client=client,
            destination=dest,
        )

    async def on_client_connect(
        self,
        client: Connection,
    ) -> Destination | None:
        if not (data := await client.read()):
            return None
        try:
            return await self._protocol(client, data)
        except (SocksIncorrectVersionError, SocksPackageError):
            return None
        except SocksRejectError:
            return None

    @staticmethod
    async def start_messaging(
        client: Connection,
        target: Connection,
    ) -> None:
        client.status = Status.MESSAGING
        tasks: dict[Connection, asyncio.Task] = {
            client: asyncio.create_task(client.read()),
            target: asyncio.create_task(target.read()),
        }
        conns = set(tasks.keys())
        closed = False
        started_at = datetime.now()
        logger.info(f'START MESSAGING {client} -> {target}')
        while not closed:
            try:
                done, _ = await asyncio.wait(
                    tasks.values(),
                    return_when=asyncio.FIRST_COMPLETED,
                )
            except TimeoutError:
                print_exc()
                break
            for conn, task in tasks.items():
                if task not in done:
                    continue
                another: Connection = (conns - {conn}).pop()
                data = task.result()
                if not data:
                    closed = True
                    break
                tasks[conn] = asyncio.create_task(conn.read())
                await another.write(data)
                if conn is client:
                    logger.info(f'{client} -> {len(data)} bytes -> {target}')
                else:
                    logger.info(f'{client} <- {len(data)} bytes <- {target}')
        logger.info(
            f'STOP MESSAGING {client} -> {target} (duration {datetime.now() - started_at})'
        )
        for task in tasks.values():
            if not task.cancelled():
                task.cancel()
        client.status = Status.CLOSED
