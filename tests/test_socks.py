import asyncio
import ipaddress
from contextlib import suppress
from socket import gethostbyname

import httpx
import pytest
import pytest_asyncio
from httpx_socks import AsyncProxyTransport
from python_socks import ProxyError

import soxy


def resolver(
    domain_name: str,
) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(gethostbyname(domain_name))


def err_resolver(
    _: str,
) -> ipaddress.IPv4Address:
    return ValueError


def socks4_auther(username: str) -> bool:
    return username == 'user'


def socks5_auther(username: str, password: str) -> bool:
    return username == 'user' and password == 'secret'  # noqa: S105


@pytest_asyncio.fixture(autouse=True)
async def run_proxy_server(
    socks: soxy.Socks4 | soxy.Socks5,
) -> None:
    async with soxy.Proxy(
        protocol=socks,
        transport=soxy.TcpTransport(),
        ruleset=soxy.Ruleset(
            allow_connecting_rules=[
                soxy.ConnectingRule(
                    from_addresses=ipaddress.IPv4Network('0.0.0.0/0'),
                )
            ],
            allow_proxying_rules=[
                soxy.ProxyingRule(
                    from_addresses=ipaddress.IPv4Network('0.0.0.0/0'),
                    to_addresses=ipaddress.IPv4Network('0.0.0.0/0'),
                ),
            ],
        ),
    ) as app:
        task = asyncio.create_task(app.serve_forever())
        yield task
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@pytest.mark.parametrize(
    ('socks', 'proxy_url', 'is_socks4a', 'exc'),
    [
        pytest.param(
            soxy.Socks4(),
            'socks4://127.0.0.1:1080',
            False,
            None,
            id='ok',
        ),
        pytest.param(
            soxy.Socks4(),
            'socks4://127.0.0.1:1080',
            True,
            ProxyError,
            id='resolve na',
        ),
        pytest.param(
            soxy.Socks4(resolver=resolver),
            'socks4://127.0.0.1:1080',
            False,
            None,
            id='resolve local ok',
        ),
        pytest.param(
            soxy.Socks4(resolver=resolver),
            'socks4://127.0.0.1:1080',
            True,
            None,
            id='resolve remote ok',
        ),
        pytest.param(
            soxy.Socks4(resolver=err_resolver),
            'socks4://127.0.0.1:1080',
            True,
            ProxyError,
            id='resolve remote err',
        ),
        pytest.param(
            soxy.Socks4(auther=socks4_auther),
            'socks4://user:secret@127.0.0.1:1080',
            False,
            None,
            id='auth ok',
        ),
        pytest.param(
            soxy.Socks4(auther=socks4_auther),
            'socks4://wow:secret@127.0.0.1:1080',
            False,
            ProxyError,
            id='auth err',
        ),
        pytest.param(
            soxy.Socks4(auther=socks4_auther, resolver=resolver),
            'socks4://user:secret@127.0.0.1:1080',
            True,
            None,
            id='auth and resolve ok',
        ),
    ],
)
@pytest.mark.socks
@pytest.mark.asyncio
async def test_socks4(
    run_proxy_server: None,  # noqa: ARG001
    proxy_url: str,
    is_socks4a: bool,
    exc: type[Exception] | None,
) -> None:
    async with httpx.AsyncClient(
        timeout=5,
        transport=AsyncProxyTransport.from_url(
            proxy_url,
            rdns=is_socks4a,
        ),
    ) as client:
        if exc is None:
            await client.get('https://httbin.org/get')
            return
        with pytest.raises(exc):
            await client.get('https://httbin.org/get')


@pytest.mark.parametrize(
    ('socks', 'proxy_url', 'is_socks5h', 'exc'),
    [
        pytest.param(
            soxy.Socks5(),
            'socks5://127.0.0.1:1080',
            False,
            None,
            id='ok',
        ),
        pytest.param(
            soxy.Socks5(),
            'socks5://127.0.0.1:1080',
            True,
            ProxyError,
            id='resolve na',
        ),
        pytest.param(
            soxy.Socks5(resolver=resolver),
            'socks5://127.0.0.1:1080',
            False,
            None,
            id='resolve local ok',
        ),
        pytest.param(
            soxy.Socks5(resolver=resolver),
            'socks5://127.0.0.1:1080',
            True,
            None,
            id='resolve remote ok',
        ),
        pytest.param(
            soxy.Socks5(resolver=err_resolver),
            'socks5://127.0.0.1:1080',
            True,
            ProxyError,
            id='resolve remote err',
        ),
        pytest.param(
            soxy.Socks5(auther=socks5_auther),
            'socks5://user:secret@127.0.0.1:1080',
            False,
            None,
            id='auth ok',
        ),
        pytest.param(
            soxy.Socks5(auther=socks5_auther),
            'socks5://wow:secret@127.0.0.1:1080',
            False,
            ProxyError,
            id='auth err',
        ),
        pytest.param(
            soxy.Socks5(auther=socks5_auther, resolver=resolver),
            'socks5://user:secret@127.0.0.1:1080',
            True,
            None,
            id='auth and resolve ok',
        ),
    ],
)
@pytest.mark.socks
@pytest.mark.asyncio
async def test_socks5(
    run_proxy_server: None,  # noqa: ARG001
    proxy_url: str,
    is_socks5h: bool,
    exc: type[Exception] | None,
) -> None:
    async with httpx.AsyncClient(
        timeout=5,
        transport=AsyncProxyTransport.from_url(
            proxy_url,
            rdns=is_socks5h,
        ),
    ) as client:
        if exc is None:
            await client.get('https://httbin.org/get')
            return
        with pytest.raises(exc):
            await client.get('https://httbin.org/get')
