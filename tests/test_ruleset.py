from logging import getLogger, basicConfig

from httpx import AsyncClient, Response
from httpx_socks import AsyncProxyTransport, ProxyError
from pytest import mark

from soxyproxy.consts import Socks5ConnectionReply, Socks4Reply

logger = getLogger(__name__)
basicConfig(level="DEBUG")


@mark.asyncio
async def test_client_block_all(
    run_socks4_server_with_client_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks4://127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        try:
            response = await client.get("https://httpbin.org/get")
            assert not response
        except ConnectionAbortedError:
            pass


@mark.asyncio
async def test_proxy_block_by_to_address(
    run_socks4_server_with_proxy_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url('socks4://127.0.0.1:8888')
    async with AsyncClient(transport=transport) as client:
        try:
            response = await client.get("https://8.8.8.8")
            assert not response
        except ProxyError as err:
            assert err.error_code == Socks4Reply.REJECTED, err


@mark.asyncio
async def test_correct_request_with_proxy_user_with_partilal_blocked_ruleset(
    run_socks5_server_with_proxy_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url("socks5://someuser:mypass@127.0.0.1:8888")
    async with AsyncClient(transport=transport) as client:
        response: Response = await client.get("https://httpbin.org/get")
        assert response


@mark.asyncio
async def test_blocked_request_with_proxy_user_with_partilal_blocked_ruleset(
    run_socks5_server_with_proxy_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url("socks5://someuser:mypass@127.0.0.1:8888")
    async with AsyncClient(transport=transport) as client:

        try:
            response = await client.get("https://8.8.8.8")
            assert not response
        except ProxyError as err:
            assert err.error_code == Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET, err


@mark.asyncio
async def test_blocked_request_with_proxy_user_with_blocked_all_ruleset(
    run_socks5_server_with_proxy_block_rule,  # noqa
) -> None:
    transport = AsyncProxyTransport.from_url("socks5://blocked:mypass@127.0.0.1:8888")
    async with AsyncClient(transport=transport) as client:
        try:
            response = await client.get("https://httpbin.org/get")
            assert not response
        except ProxyError as err:
            assert err.error_code == Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET, err
