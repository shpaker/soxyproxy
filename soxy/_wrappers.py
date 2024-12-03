import asyncio
import typing
from ipaddress import IPv4Address
from traceback import print_exc

from soxy._types import (
    Resolver,
    Socks4AsyncAuther,
    Socks4Auther,
    Socks5AsyncAuther,
    Socks5Auther,
)

_A = typing.TypeVar('_A')
_R = typing.TypeVar('_R')


def auther_wrapper(
    _func: Socks4Auther | Socks5Auther | Socks4AsyncAuther | Socks5AsyncAuther,
) -> Socks4AsyncAuther | Socks5AsyncAuther:
    async def _inner(
        *args: str,
        **kwargs: str,
    ) -> bool:
        try:
            result: bool = (
                await _func(*args, **kwargs)  # type: ignore[assignment]
                if asyncio.iscoroutinefunction(_func)
                else _func(*args, **kwargs)
            )
        except Exception:  # noqa: BLE001
            print_exc()
            result = False
        return result

    return _inner


def resolver_wrapper(
    _func: Resolver,
) -> typing.Callable[[str], typing.Awaitable[IPv4Address | None]]:
    async def _inner(
        name: str,
    ) -> IPv4Address | None:
        try:
            result: IPv4Address | None = (
                await _func(name) if asyncio.iscoroutinefunction(_func) else _func(name)  # type: ignore[assignment]
            )
        except Exception:  # noqa: BLE001
            print_exc()
            return None
        return result

    return _inner
