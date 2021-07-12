from logging import basicConfig, getLogger

from httpx import AsyncClient, Response
from httpx_socks import ProxyError
from pytest import mark

from soxyproxy.consts import Socks5ConnectionReply

logger = getLogger(__name__)
basicConfig(level="DEBUG")


@mark.asyncio
async def test_correct_domain_request(
    run_socks5_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5")
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()


@mark.asyncio
async def test_correct_incorrect_domain_request(
    run_socks5_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5")
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://wbshcbnQOKWPOD.jhbjhbjhbjhbjhb")
            assert not res
        except ProxyError as err:
            assert err


@mark.asyncio
async def test_correct_ip_request(
    run_socks5_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5")
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://8.8.8.8")
        res.raise_for_status()


@mark.asyncio
async def test_correct_auth_request(
    run_socks5_auth_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5", "someuser", "mypass")
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()


@mark.asyncio
async def test_incorrect_auth_request(
    run_socks5_auth_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5", "qwerty", "asdfg")
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://httpbin.org/get")
            res.raise_for_status()
        except ProxyError:
            pass


@mark.asyncio
async def test_incorrect_request(
    run_socks5_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks5")
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://127.0.0.1:9449/get")
            res.raise_for_status()
        except ProxyError as err:
            assert err.error_code == Socks5ConnectionReply.HOST_UNREACHABLE
