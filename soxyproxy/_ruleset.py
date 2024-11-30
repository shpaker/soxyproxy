from soxyproxy._logger import logger
from soxyproxy._types import (
    Connection,
    Address,
    IPvAnyAddress,
    IPvAnyNetwork,
)

from soxyproxy._utils import match_destination


class Rule:
    def __init__(
        self,
        from_address: IPvAnyAddress | IPvAnyNetwork,
        to_address: IPvAnyAddress | IPvAnyNetwork,
    ) -> None:
        self._from_address = from_address
        self._to_address = to_address

    def __call__(
        self,
        client: Connection,
        destination: Address,
    ) -> bool:
        return match_destination(
            destination=client.address,
            math_with=self._from_address,
        ) and match_destination(
            destination=destination,
            math_with=self._to_address,
        )

    def __repr__(
        self,
    ) -> str:
        return f"<{self.__class__.__name__}: from {self._from_address} to {self._to_address}>"


class Ruleset:
    def __init__(
        self,
        allow_rules: list[Rule] | None = None,
        block_rules: list[Rule] | None = None,
    ) -> None:
        self._allow_rules = allow_rules or []
        self._block_rules = block_rules or []

    def __call__(
        self,
        client: Connection,
        destination: Address,
    ) -> bool:
        result = None
        for rule in self._allow_rules:
            if result := rule(
                client=client,
                destination=destination,
            ):
                logger.info(f"{client} request ALLOWED by {rule}")
                break
        for rule in self._block_rules:
            if result := rule(
                client=client,
                destination=destination,
            ):
                logger.info(f"{client} request BLOCKED by {rule}")
                return False
        if result is None:
            result = False
            logger.info(
                f"{client} not found allow-rule for {destination.address}:{destination.port}"
            )
        return result
