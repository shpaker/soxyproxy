from ipaddress import IPv4Address
from unittest.mock import AsyncMock

import pytest

from soxy import (
    Address,
    PackageError,
    RejectError,
    ResolveDomainError,
)
from soxy import Socks4, Connection

socks = Socks4()


@pytest.mark.asyncio
async def test_resolver_ok() -> None:
    class _FakeConn(Connection): ...

    socks = Socks4(
        resolver=lambda value: IPv4Address("1.1.1.1"),
    )
    results = await socks(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00google.com\x00",
    )
    assert results == Address(
        address=IPv4Address("1.1.1.1"),
        port=443,
    )


@pytest.mark.asyncio
async def test_resolver_fail() -> None:
    class _FakeConn(Connection): ...

    def resolver(name: str) -> None:
        raise ResolveDomainError

    socks = Socks4(
        resolver=resolver,
    )
    with pytest.raises(RejectError):
        await socks(
            _FakeConn(),
            data=b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00google.com\x00",
        )


@pytest.mark.asyncio
async def test_ok() -> None:
    write_mock = AsyncMock()

    class _FakeConn(Connection):
        write = write_mock

    results = await socks(
        _FakeConn(),
        data=b"\x04\x01\x01\xbb\x8e\xfaJ.\x00",
    )
    assert results == Address(
        address=IPv4Address("142.250.74.46"),
        port=443,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data", "exception", "write_called"),
    [
        pytest.param(
            b"\x05\x01\x01\xbb\x8e\xfaJ.\x00",
            PackageError,
            False,
            id="incorrect version",
        ),
        pytest.param(
            b"\x05\x01\x01\xbb\x8e\xfaJ.\x00\x05\x01\x01\xbb\x8e\xfaJ.\x00",
            PackageError,
            False,
            id="too large",
        ),
        pytest.param(
            b"\x04\x01\x01\xbb\x8e\xfaJ.\x01",
            PackageError,
            False,
            id="reserved not null",
        ),
        pytest.param(
            b"\x04\x00\x01\xbb\x8e\xfaJ.\x00",
            RejectError,
            True,
            id="unknown command",
        ),
        pytest.param(
            b"\x04\x02\x01\xbb\x8e\xfaJ.\x00",
            RejectError,
            True,
            id="bind command",
        ),
    ],
)
async def test_error(
    data: bytes,
    exception: type[Exception],
    write_called: bool,
) -> None:
    write_mock = AsyncMock()

    class _FakeConn(Connection):
        write = write_mock

    with pytest.raises(exception):
        await socks(
            _FakeConn(),
            data=data,
        )

    if not write_called:
        write_mock.assert_not_called()
    else:
        write_mock.assert_called_once()
