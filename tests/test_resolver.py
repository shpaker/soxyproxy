import asyncio
import socket
import typing
from ipaddress import IPv4Address, IPv6Address

import pytest

from soxy import SystemResolver

_IPV4 = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))
_IPV6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:2800:220:1:248:1893:25c8:1946', 0, 0, 0))


def patch_getaddrinfo(
    monkeypatch: pytest.MonkeyPatch,
    result: list[typing.Any] | BaseException | None = None,
    delay: float = 0,
) -> None:
    async def getaddrinfo(*args: object, **kwargs: object) -> list[typing.Any]:  # noqa: ARG001
        await asyncio.sleep(delay)
        if isinstance(result, BaseException):
            raise result
        return result or []

    monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', getaddrinfo)


@pytest.mark.asyncio
async def test_system_resolver_localhost() -> None:
    assert await SystemResolver()('localhost') == IPv4Address('127.0.0.1')


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        pytest.param('127.0.0.1', IPv4Address('127.0.0.1'), id='ipv4'),
        pytest.param('::1', IPv6Address('::1'), id='ipv6'),
    ],
)
@pytest.mark.asyncio
async def test_system_resolver_ip_literal(name: str, expected: IPv4Address | IPv6Address) -> None:
    assert await SystemResolver()(name) == expected


@pytest.mark.asyncio
async def test_system_resolver_prefers_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_getaddrinfo(monkeypatch, [_IPV6, _IPV4])
    assert await SystemResolver()('example.com') == IPv4Address('93.184.216.34')


@pytest.mark.asyncio
async def test_system_resolver_ipv6_only(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_getaddrinfo(monkeypatch, [_IPV6])
    assert await SystemResolver()('example.com') == IPv6Address('2606:2800:220:1:248:1893:25c8:1946')


@pytest.mark.parametrize(
    'result',
    [
        pytest.param(socket.gaierror(socket.EAI_NONAME, 'Name or service not known'), id='not found'),
        pytest.param([], id='no addresses'),
    ],
)
@pytest.mark.asyncio
async def test_system_resolver_unresolvable(
    monkeypatch: pytest.MonkeyPatch,
    result: list[typing.Any] | BaseException,
) -> None:
    patch_getaddrinfo(monkeypatch, result)
    assert await SystemResolver()('example.com') is None


@pytest.mark.asyncio
async def test_system_resolver_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_getaddrinfo(monkeypatch, [_IPV4], delay=10)
    async with asyncio.timeout(1):
        assert await SystemResolver(timeout=0.05)('example.com') is None
