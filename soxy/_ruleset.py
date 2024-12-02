from soxy._logger import logger
from soxy._types import (
    Address,
    Connection,
    IPvAnyAddress,
    IPvAnyNetwork,
)
from soxy._utils import match_addresses


class Rule:
    def __init__(
        self,
        from_addresses: IPvAnyAddress | IPvAnyNetwork,
        to_addresses: IPvAnyAddress | IPvAnyNetwork | str,
    ) -> None:
        self._from_addresses = from_addresses
        self._to_addresses = to_addresses

    def __call__(
        self,
        client: Connection,
        destination: Address,
        domain_name: str | None,
    ) -> bool:
        if isinstance(self._to_addresses, str):
            return not (
                not isinstance(domain_name, str) or domain_name != self._to_addresses
            )
        return match_addresses(
            destination=client.address,
            math_with=self._from_addresses,
        ) and match_addresses(
            destination=destination,
            math_with=self._to_addresses,
        )

    def __repr__(
        self,
    ) -> str:
        return f"<{self.__class__.__name__}: from {self._from_addresses} to {self._to_addresses}>"


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
        domain_name: str | None,
    ) -> bool:
        result = None
        for rule in self._allow_rules:
            if result := rule(
                client=client,
                destination=destination,
                domain_name=domain_name,
            ):
                logger.info(f"{client} request ALLOWED by {rule}")
                break
        for rule in self._block_rules:
            if result := rule(
                client=client,
                destination=destination,
                domain_name=domain_name,
            ):
                logger.info(f"{client} request BLOCKED by {rule}")
                return False
        if result is None:
            result = False
            logger.info(
                f"{client} not found allow-rule for {destination.ip}:{destination.port}"
            )
        return result
