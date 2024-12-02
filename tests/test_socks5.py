from ipaddress import IPv4Address
from unittest.mock import AsyncMock

import pytest

from soxy import (
    Address,
    Connection,
    RejectError,
    Resolver,
    Socks5,
)


class _FakeConn(Connection):
    read = AsyncMock(
        return_value=b"\x05\x01\x00\x01\x8e\xfaJ#\x01\xbb",
    )


@pytest.mark.asyncio
async def test_ok() -> None:
    results = await Socks5()(
        _FakeConn(),
        data=b"\x05\x02\x00\x01",
    )
    assert results == (
        Address(
            ip=IPv4Address("142.250.74.35"),
            port=443,
        ),
        None,
    )


@pytest.mark.asyncio
async def test_resolver_ok(
    resolver: Resolver,
) -> None:
    class _FakeConn(Connection):
        read = AsyncMock(
            return_value=b"\x05\x01\x00\x03\tgoogle.com\x01\xbb",
        )
        write = AsyncMock()

    socks = Socks5(
        resolver=resolver,
    )
    results = await socks(
        _FakeConn,
        data=b"\x05\x02\x00\x01",
    )
    assert results == (
        Address(
            ip=IPv4Address("1.1.1.1"),
            port=443,
        ),
        "google.com",
    )


@pytest.mark.asyncio
async def test_resolver_fail(
    resolver: Resolver,
) -> None:
    class _FakeConn(Connection):
        read = AsyncMock(
            return_value=b"\x05\x01\x00\x03\tgoogle.cm\x01\xbb",
        )
        write = AsyncMock()

    socks = Socks5(
        resolver=resolver,
    )
    with pytest.raises(RejectError):
        await socks(
            _FakeConn,
            data=b"\x05\x02\x00\x01",
        )
