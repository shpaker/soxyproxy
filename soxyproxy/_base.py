from abc import ABC, abstractmethod

from soxyproxy._errors import (
    Destination,
    SocksRejectError,
)
from soxyproxy._types import (
    Connection,
    ProxySocks,
)


class BaseSocks(
    ABC,
    ProxySocks,
):
    @abstractmethod
    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        pass

    @abstractmethod
    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> SocksRejectError:
        pass

    @abstractmethod
    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Destination:
        pass
