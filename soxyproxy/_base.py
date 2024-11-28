from abc import ABC, abstractmethod

from soxyproxy._errors import (
    RejectError,
)
from soxyproxy._types import (
    Connection,
    Destination,
    DomainNameResolver,
)


class BaseSocks(
    ABC,
    # ProxySocks,
):
    def __init__(
        self,
        domain_names_resolver: DomainNameResolver | None = None,
    ) -> None:
        self._domain_names_resolver = domain_names_resolver

    @abstractmethod
    async def success(
        self,
        client: Connection,
        destination: Destination,
    ) -> RejectError:
        pass

    @abstractmethod
    async def target_unreachable(
        self,
        client: Connection,
        destination: Destination,
    ) -> RejectError:
        pass

    @abstractmethod
    async def __call__(
        self,
        client: Connection,
        data: bytes,
    ) -> Destination:
        pass
