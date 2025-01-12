from soxy._logger import logger
from soxy._types import (
    Address,
    Connection,
    IPvAnyAddress,
    IPvAnyNetwork,
)
from soxy._utils import match_addresses


class ConnectingRule:
    def __init__(
        self,
        from_addresses: IPvAnyAddress | IPvAnyNetwork,
    ) -> None:
        self._from_addresses = from_addresses

    def __call__(
        self,
        client: Connection,
    ) -> bool:
        return match_addresses(
            address=client.address,
            math_with=self._from_addresses,
        )

    def __repr__(
        self,
    ) -> str:
        return f'<{self.__class__.__name__}: {self._from_addresses}>'


class ProxyingRule:
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
            return not (not isinstance(domain_name, str) or domain_name != self._to_addresses)
        return match_addresses(
            address=client.address,
            math_with=self._from_addresses,
        ) and match_addresses(
            address=destination,
            math_with=self._to_addresses,
        )

    def __repr__(
        self,
    ) -> str:
        return f'<{self.__class__.__name__}: from {self._from_addresses} to {self._to_addresses}>'


class Ruleset:
    def __init__(
        self,
        allow_connecting_rules: list[ConnectingRule],
        allow_proxying_rules: list[ProxyingRule],
        block_connecting_rules: list[ConnectingRule] | None = None,
        block_proxying_rules: list[ProxyingRule] | None = None,
    ) -> None:
        self._allow_connecting_rules = allow_connecting_rules or []
        self._block_connecting_rules: list[ConnectingRule] = block_connecting_rules or []
        self._allow_proxying_rules = allow_proxying_rules or []
        self._block_proxying_rules: list[ProxyingRule] = block_proxying_rules or []

    def should_allow_connecting(
        self,
        client: Connection,
    ) -> bool:
        result: bool | None = None
        for rule in self._allow_connecting_rules:
            if result := rule(
                client=client,
            ):
                logger.info(f'{client} connecting ALLOWED: {rule}')
                break
        for rule in self._block_connecting_rules:
            if result := rule(
                client=client,
            ):
                logger.info(f'{client} connecting BLOCKED: {rule}')
                return False
        if result is None:
            result = False
            logger.info(
                f'{client} not found allow-connecting-rule',
            )
        return result

    def should_allow_proxying(
        self,
        client: Connection,
        destination: Address,
        domain_name: str | None,
    ) -> bool:
        result: bool | None = None
        for rule in self._allow_proxying_rules:
            if result := rule(
                client=client,
                destination=destination,
                domain_name=domain_name,
            ):
                logger.info(f'{client} request ALLOWED by {rule}')
                break
        for rule in self._block_proxying_rules:
            if result := rule(
                client=client,
                destination=destination,
                domain_name=domain_name,
            ):
                logger.info(f'{client} request BLOCKED by {rule}')
                return False
        if result is None:
            result = False
            logger.info(
                f'{client} not found allow-rule for {destination.ip}:{destination.port}',
            )
        return result
