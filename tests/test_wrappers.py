from ipaddress import IPv4Address

import pytest

from soxy._wrappers import auther_wrapper, resolver_wrapper


@pytest.mark.asyncio
async def test_auther_wrapper_sync() -> None:
    def sync_auther(*args: str, **kwargs: str) -> bool:
        return True

    wrapped_auther = auther_wrapper(sync_auther)
    result = await wrapped_auther()
    assert result is True


@pytest.mark.asyncio
async def test_auther_wrapper_async() -> None:
    async def async_auther(*args: str, **kwargs: str) -> bool:
        return True

    wrapped_auther = auther_wrapper(async_auther)
    result = await wrapped_auther()
    assert result is True


@pytest.mark.asyncio
async def test_auther_wrapper_exception() -> None:
    def sync_auther(*args: str, **kwargs: str) -> bool:
        msg = 'Test exception'
        raise Exception(msg)

    wrapped_auther = auther_wrapper(sync_auther)
    result = await wrapped_auther()
    assert result is False


@pytest.mark.asyncio
async def test_resolver_wrapper_sync() -> None:
    def sync_resolver(name: str) -> IPv4Address:
        return IPv4Address('127.0.0.1')

    wrapped_resolver = resolver_wrapper(sync_resolver)
    result = await wrapped_resolver('localhost')
    assert result == IPv4Address('127.0.0.1')


@pytest.mark.asyncio
async def test_resolver_wrapper_async() -> None:
    async def async_resolver(name: str) -> IPv4Address:
        return IPv4Address('127.0.0.1')

    wrapped_resolver = resolver_wrapper(async_resolver)
    result = await wrapped_resolver('localhost')
    assert result == IPv4Address('127.0.0.1')


@pytest.mark.asyncio
async def test_resolver_wrapper_exception() -> None:
    def sync_resolver(name: str) -> IPv4Address:
        msg = 'Test exception'
        raise ValueError(msg)

    wrapped_resolver = resolver_wrapper(sync_resolver)
    result = await wrapped_resolver('localhost')
    assert result is None
