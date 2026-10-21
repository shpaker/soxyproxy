import asyncio
import socket
import types
import typing

from soxy._config import Config
from soxy._errors import (
    PackageError,
    ProtocolError,
)
from soxy._logger import logger
from soxy._ruleset import Ruleset
from soxy._types import (
    Address,
    Connection,
    ProxySocks,
    Transport,
)


class Proxy:
    def __init__(
        self,
        protocol: ProxySocks,
        ruleset: Ruleset,
        transport: Transport,
    ) -> None:
        self._protocol = protocol
        transport.init(
            on_client_connected_cb=self._on_client_connected_transport_cb,
            start_messaging_cb=self._start_messaging_transport_cb,
            on_remote_unreachable_cb=self._on_remote_connection_unreachable_cb,
        )
        logger.info(f'initialized {transport} for {protocol}')
        self._transport = transport
        self._ruleset = ruleset
        self._server: asyncio.Server | None = None

    async def __aenter__(
        self,
    ) -> typing.Self:
        logger.info(f'{self} start serving')
        self._server = await self._transport.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_traceback: types.TracebackType | None,
    ) -> None:
        logger.info(f'{self} shutdown')
        self._server = None
        await self._transport.__aexit__(
            exc_type,
            exc_value,
            exc_traceback,
        )

    @property
    def sockets(
        self,
    ) -> tuple[socket.socket, ...]:
        if self._server is None:
            msg = f'{self} is not started'
            raise RuntimeError(msg)
        return self._server.sockets

    async def serve_forever(
        self,
    ) -> None:
        """
        Serve until cancelled. Connections are closed on exiting the context manager.

        asyncio.Server.serve_forever() is not used here because on cancellation
        it waits for all client connections to be closed by peers.
        """
        if self._server is None:
            msg = f'{self} is not started'
            raise RuntimeError(msg)
        await asyncio.get_running_loop().create_future()

    @classmethod
    def from_config(
        cls,
        config: Config,
    ) -> typing.Self:
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
        if (
            self._ruleset.should_allow_connecting(
                client=client,
            )
            is False
        ):
            return None
        try:
            address, domain_name = await self._protocol(client)
        except PackageError as exc:
            logger.info(f'{client} package error ({exc.data!r})')
            return None
        except ProtocolError as exc:
            logger.info(f'{client} protocol error ({exc.__class__.__name__})')
            return None
        if self._ruleset.should_allow_proxying(
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
        await self._protocol.success(
            client=client,
            destination=remote.local_address,
        )

    async def _on_remote_connection_unreachable_cb(
        self,
        client: Connection,
        destination: Address,
        error: OSError,
    ) -> None:
        logger.info(f'{client} remote {destination.ip}:{destination.port} unreachable ({error!r})')
        await self._protocol.target_unreachable(
            client=client,
            destination=destination,
            error=error,
        )
