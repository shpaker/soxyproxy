from logging import getLogger, basicConfig

from httpx import AsyncClient, Response
from httpx_socks import AsyncProxyTransport, ProxyError
from pytest import mark

from soxyproxy.consts import Socks5ConnectionReplies

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


@mark.asyncio
async def test_correct_auth_request(
    run_socks5_auth_server,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks5://test:qwerty@127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()


@mark.asyncio
async def test_incorrect_auth_request(
    run_socks5_auth_server,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks5://test:123456@127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://httpbin.org/get")
            res.raise_for_status()
        except ProxyError as err:
            pass
            # assert err.error_code == Socks5ConnectionReplies.HOST_UNREACHABLE


@mark.asyncio
async def test_incorrect_request(
    run_socks5_server,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks5://127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://127.0.0.1:9449/get")
            res.raise_for_status()
        except ProxyError as err:
            assert err.error_code == Socks5ConnectionReplies.HOST_UNREACHABLE
