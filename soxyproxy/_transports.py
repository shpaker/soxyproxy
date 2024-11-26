import asyncio

from soxyproxy._connection import TCPConnection
from soxyproxy._service import ProxyService
from soxyproxy._types import ProxyTransport


class TcpTransport(
    ProxyTransport,
):
    def __init__(
        self,
        proxy: ProxyService,
        host: str = "127.0.0.1",
        port: int = 1080,
    ) -> None:
        self._service = proxy
        self._async_server_factory = asyncio.start_server(
            client_connected_cb=self._client_cb,
            host=host,
            port=port,
        )

    async def __aenter__(self):
        return await self._async_server_factory

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"

    async def _client_cb(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with TCPConnection(reader, writer) as client:
            if not (
                destination := await self._service.on_client_connect(client)
            ) or isinstance(destination.address, str):
                return
            try:
                async with await TCPConnection.open(
                    host=str(destination.address),
                    port=destination.port,
                ) as target:
                    await self._service.on_target_open(client, destination)
                    await self._service.start_messaging(client, target)
            except ConnectionError:
                await self._service.on_target_unreachable(client, destination)
