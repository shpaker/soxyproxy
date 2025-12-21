import inspect
import typing

from soxy._logger import logger

if typing.TYPE_CHECKING:
    from ipaddress import IPv4Address

    from soxy._types import (
        Resolver,
        Socks4AsyncAuther,
        Socks4Auther,
        Socks5AsyncAuther,
        Socks5Auther,
    )


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
                if inspect.iscoroutinefunction(_func)
                else _func(*args, **kwargs)
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception('Error in auther_wrapper', exc_info=exc)
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
                await _func(name) if inspect.iscoroutinefunction(_func) else _func(name)  # type: ignore[assignment]
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception('Error in resolver_wrapper', exc_info=exc)
            return None
        return result

    return _inner
