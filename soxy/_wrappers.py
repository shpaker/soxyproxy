import asyncio
import inspect
import typing
from ipaddress import IPv4Address, IPv6Address

from soxy._logger import logger
from soxy._types import (
    IPvAnyAddress,
    Resolver,
)


def _is_async_callable(
    func: typing.Callable[..., typing.Any],
) -> bool:
    return inspect.iscoroutinefunction(func) or inspect.iscoroutinefunction(
        getattr(func, '__call__', None),  # noqa: B004
    )


def auther_wrapper[**P](
    _func: typing.Callable[P, bool | typing.Awaitable[bool]],
) -> typing.Callable[P, typing.Awaitable[bool]]:
    async def _inner(
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> bool:
        try:
            result = _func(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.exception('Error in auther_wrapper', exc_info=exc)
            return False
        return bool(result)

    return _inner


def resolver_wrapper(
    _func: Resolver,
) -> typing.Callable[[str], typing.Awaitable[IPvAnyAddress | None]]:
    async def _inner(
        name: str,
    ) -> IPvAnyAddress | None:
        try:
            # sync resolvers usually block (e.g. socket.gethostbyname), so keep them off the event loop
            result = _func(name) if _is_async_callable(_func) else await asyncio.to_thread(_func, name)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.exception('Error in resolver_wrapper', exc_info=exc)
            return None
        if result is not None and not isinstance(result, IPv4Address | IPv6Address):
            logger.warning(f'resolver returned {result!r} for {name}')
            return None
        return result

    return _inner
