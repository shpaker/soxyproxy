from ipaddress import IPv4Address
from unittest.mock import AsyncMock

import pytest

from soxy import (
    Address,
    Connection,
    PackageError,
    RejectError,
    ResolveDomainError,
    Resolver,
    Socks4,
)


class _FakeConn(Connection):
    _address = Address(ip=IPv4Address(0), port=0)


@pytest.mark.asyncio
async def test_ok() -> None:
    results = await Socks4()(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\x8e\xfaJ.\x00",
    )
    assert results == (
        Address(
            ip=IPv4Address("142.250.74.46"),
            port=443,
        ),
        None,
    )


@pytest.mark.asyncio
async def test_auther_ok() -> None:
    socks = Socks4(
        auther=lambda name: name == "foo",
    )
    results = await socks(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\xac\xd9\x15\xa3foo\x00",
    )
    assert results == (
        Address(
            ip=IPv4Address("172.217.21.163"),
            port=443,
        ),
        None,
    )


@pytest.mark.asyncio
async def test_auther_fail() -> None:
    socks = Socks4(
        auther=lambda name: name == "foo",
    )
    with pytest.raises(RejectError):
        await socks(
            _FakeConn(),
            data=b"\x04\x01\x01\xbb\xac\xd9\x15\xa3bar\x00",
        )


@pytest.mark.asyncio
async def test_resolver_ok(
    resolver: Resolver,
) -> None:
    socks = Socks4(
        resolver=resolver,
    )
    results = await socks(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00google.com\x00",
    )
    assert results == (
        Address(
            ip=IPv4Address("1.1.1.1"),
            port=443,
        ),
        "google.com",
    )


@pytest.mark.asyncio
async def test_resolver_fail() -> None:
    def resolver(domain_name: str) -> None:
        raise ResolveDomainError(domain_name=domain_name, port=0)

    socks = Socks4(
        resolver=resolver,
    )
    with pytest.raises(RejectError):
        await socks(
            _FakeConn(),
            data=b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00google.com\x00",
        )


@pytest.mark.asyncio
async def test_auther_and_resolver_ok(
    resolver: Resolver,
) -> None:
    socks = Socks4(
        auther=lambda name: name == "foo",
        resolver=resolver,
    )
    results = await socks(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\x00\x00\x00\x01foo\x00google.com\x00",
    )
    assert results == (
        Address(ip=IPv4Address("1.1.1.1"), port=443),
        "google.com",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data",),
    [
        pytest.param(
            b"\x05\x01\x01\xbb\x8e\xfaJ.\x00",
            id="incorrect version",
        ),
        pytest.param(
            b"\x05\x01\x01\xbb\x8e\xfaJ.\x00\x05\x01\x01\xbb\x8e\xfaJ.\x00",
            id="too large",
        ),
        pytest.param(
            b"\x04\x01\x01\xbb\x8e\xfaJ.\x01",
            id="reserved not null",
        ),
    ],
)
async def test_package_error(
    data: bytes,
) -> None:
    write_mock = AsyncMock()

    class _FakeConn(Connection):
        write = write_mock

    with pytest.raises(PackageError):
        await Socks4()(
            _FakeConn(),
            data=data,
        )

    write_mock.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data",),
    [
        pytest.param(
            b"\x04\x02\x01\xbb\x8e\xfaJ.\x00",
            id="bind command",
        ),
        pytest.param(
            b"\x04\x00\x01\xbb\x8e\xfaJ.\x00",
            id="unknown command",
        ),
    ],
)
async def test_reject_error(
    data: bytes,
) -> None:
    write_mock = AsyncMock()

    class _FakeConn(Connection):
        _address = Address(ip=IPv4Address(0), port=0)
        write = write_mock

    with pytest.raises(RejectError):
        await Socks4()(
            _FakeConn(),
            data=data,
        )

    write_mock.assert_called_once()
