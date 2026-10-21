import threading
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


@pytest.mark.asyncio
async def test_resolver_wrapper_async_callable_object() -> None:
    class Resolver:
        async def __call__(self, name: str) -> IPv4Address:
            return IPv4Address('127.0.0.1')

    wrapped_resolver = resolver_wrapper(Resolver())
    assert await wrapped_resolver('localhost') == IPv4Address('127.0.0.1')


@pytest.mark.asyncio
async def test_resolver_wrapper_sync_runs_in_thread() -> None:
    loop_thread = threading.get_ident()
    resolver_thread = None

    def sync_resolver(name: str) -> IPv4Address:
        nonlocal resolver_thread
        resolver_thread = threading.get_ident()
        return IPv4Address('127.0.0.1')

    await resolver_wrapper(sync_resolver)('localhost')
    assert resolver_thread is not None
    assert resolver_thread != loop_thread


@pytest.mark.asyncio
async def test_resolver_wrapper_invalid_result() -> None:
    def sync_resolver(name: str) -> IPv4Address:
        return '127.0.0.1'  # type: ignore[return-value]

    assert await resolver_wrapper(sync_resolver)('localhost') is None


@pytest.mark.asyncio
async def test_auther_wrapper_async_callable_object() -> None:
    class Auther:
        async def __call__(self, username: str, password: str) -> bool:
            return username == 'user'

    assert await auther_wrapper(Auther())('user', 'pass') is True
    assert await auther_wrapper(Auther())('nobody', 'pass') is False


@pytest.mark.asyncio
async def test_resolver_wrapper_async_callable_object_runs_in_loop() -> None:
    loop_thread = threading.get_ident()
    resolver_thread = None

    class Resolver:
        async def __call__(self, name: str) -> IPv4Address:
            nonlocal resolver_thread
            resolver_thread = threading.get_ident()
            return IPv4Address('127.0.0.1')

    assert await resolver_wrapper(Resolver())('localhost') == IPv4Address('127.0.0.1')
    assert resolver_thread == loop_thread
