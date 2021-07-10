from logging import getLogger, basicConfig

from httpx import AsyncClient
from httpx_socks import AsyncProxyTransport
from pytest import mark

logger = getLogger(__name__)
basicConfig(level="DEBUG")


@mark.asyncio
async def test_client_block(
    run_socks4_server_with_client_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks4://127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        try:
            response = await client.get("https://httpbin.org/get")
            assert not response
        except ConnectionAbortedError:
            pass
