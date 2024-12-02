import asyncio
from datetime import datetime
from traceback import print_exc
from typing import Self

from soxy._config import Config
from soxy._errors import (
    PackageError,
    ProtocolError,
)
from soxy._logger import logger
from soxy._ruleset import Ruleset
from soxy._tcp import TcpTransport
from soxy._types import Address, Connection, ProxySocks


class Proxy:
    def __init__(
        self,
        protocol: ProxySocks,
        transport: TcpTransport | None = None,
        ruleset: Ruleset | None = None,
    ) -> None:
        self._protocol = protocol
        transport if transport is not None else TcpTransport()
        transport.init(
            on_client_connected_cb=self._on_client_connected_transport_cb,
            start_messaging_cb=self._start_messaging_transport_cb,
        )
        logger.info(f'initialized {transport} for {protocol}')
        self._transport = transport
        self._ruleset = ruleset if ruleset is not None else Ruleset()

    async def __aenter__(
        self,
    ):
        logger.info(f'{self} start serving')
        return await self._transport.__aenter__()

    async def __aexit__(
        self,
        exc_type,
        exc_val,
        exc_tb,
    ) -> None:
        logger.info(f'{self} shutdown')
        await self._transport.__aexit__(
            exc_type,
            exc_val,
            exc_tb,
        )

    @classmethod
    def from_config(
        cls,
        config: Config,
    ) -> Self:
        return cls(
            protocol=config.socks,
            transport=config.transport,
            ruleset=config.ruleset,
        )

    async def _on_client_connected_transport_cb(
        self,
        client: Connection,
    ) -> Address | None:
        logger.info(f'{client} client connected')
        if not (data := await client.read()):
            return None
        try:
            address, domain_name = await self._protocol(client, data)
        except PackageError as exc:
            logger.info(f'{client} package error ({exc.data})')
            return None
        except ProtocolError as exc:
            logger.info(f'{client} protocol error ({exc.__class__.__name__})')
            return None
        if self._ruleset(
            client=client,
            destination=address,
            domain_name=domain_name,
        ):
            return address
        await self._protocol.ruleset_reject(
            client=client,
            destination=address,
        )
        return None

    async def _start_messaging_transport_cb(
        self,
        client: Connection,
        remote: Connection,
    ) -> None:
        logger.info(f'{client} remote connection opened: {remote}')
        await self._protocol.success(
            client=client,
            destination=remote.address,
        )
        logger.info(f'{client} start messaging with {remote}')
        tasks: dict[Connection, asyncio.Task] = {
            client: asyncio.create_task(client.read()),
            remote: asyncio.create_task(remote.read()),
        }
        conns = set(tasks.keys())
        closed = False
        started_at = datetime.now()
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
                    logger.info(f'{client} -> {len(data)} bytes -> {remote}')
                else:
                    logger.info(f'{client} <- {len(data)} bytes <- {remote}')
        for task in tasks.values():
            if not task.cancelled():
                task.cancel()
        logger.info(
            f'{client} stop messaging with {remote} (duration {datetime.now() - started_at})',
        )
