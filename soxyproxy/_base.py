from abc import ABC, abstractmethod

from soxyproxy._types import (
    Address,
    Connection,
    Resolver,
)


class BaseSocks(
    ABC,
):
    def __init__(
        self,
        resolver: Resolver | None = None,
    ) -> None:
        self._resolver = resolver

    @abstractmethod
    async def success(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        pass

    @abstractmethod
    async def target_unreachable(
        self,
        client: Connection,
        destination: Address,
    ) -> None:
        pass

    @abstractmethod
    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Address:
        pass
