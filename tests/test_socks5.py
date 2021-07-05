from logging import getLogger, basicConfig

from httpx import AsyncClient, Response
from httpx_socks import AsyncProxyTransport
from pytest import mark

logger = getLogger(__name__)
basicConfig(level="DEBUG")


@mark.asyncio
async def test_correct_request(
    run_socks5_server,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks5://127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()
