from abc import ABC, abstractmethod
from asyncio import iscoroutine
from collections.abc import Callable
from ipaddress import IPv4Address
from traceback import print_exc
from typing import Any


class BaseWrapper(
    ABC,
):
    def __init__(
        self,
        func: Callable[[Any], Any],
    ) -> None:
        self._func = func

    async def _exec(
        self,
        *args: str,
        **kwargs: str,
    ) -> Any:  # noqa: ANN401
        result = self._func(*args, **kwargs)
        if iscoroutine(result):
            result = await result
        return result

    @abstractmethod
    async def __call__(
        self,
        *args: str,
        **kwargs: str,
    ) -> Any:  # noqa: ANN401
        raise NotImplementedError


class AutherWrapper[T](
    BaseWrapper,
):
    async def __call__(  # type: T
        self,
        *args: str,
        **kwargs: str,
    ) -> bool:
        try:
            result = await self._exec(*args, **kwargs)
        except Exception:  # noqa: BLE001
            print_exc()
            result = False
        return result


class ResolverWrapper(BaseWrapper):
    async def __call__(
        self,
        domain_name: str,
    ) -> IPv4Address | None:
        try:
            result = await self._exec(domain_name)
        except Exception:  # noqa: BLE001
            print_exc()
            return None
        return result
