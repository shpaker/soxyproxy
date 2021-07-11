from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Optional, Union

from soxyproxy.exceptions import SocksRulesetError
from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import ConnectionRule, ProxyRule, RuleAction, RuleSet

DEFAULT_RULE_ACTION = RuleAction.PASS


def check_matched_from(
    client: ClientModel,
    rule: Union[ConnectionRule, ProxyRule],
) -> bool:
    if not rule.from_address:
        return True
    from_is_network = isinstance(rule.from_address, (IPv4Network, IPv6Network))
    if from_is_network and client.host in rule.from_address:  # type: ignore
        return True
    if not from_is_network and rule.from_address == client.host:
        return True
    return False


def check_matched_to(
    request_to: Union[IPv4Address, IPv6Address],
    rule: ProxyRule,
) -> bool:
    if not rule.to_address:
        return True
    from_is_network = isinstance(rule.from_address, (IPv4Network, IPv6Network))
    if from_is_network and request_to in rule.to_address:  # type: ignore
        return True
    if not from_is_network and rule.to_address == request_to:
        return True
    return False


def check_connection_rules(
    client: ClientModel,
    ruleset: RuleSet,
) -> Optional[ConnectionRule]:
    for rule in reversed(ruleset.connection):
        if not isinstance(rule, ConnectionRule):
            continue
        if check_matched_from(client, rule):
            return rule
    return None


def raise_for_connection_rules(
    client: ClientModel,
    ruleset: RuleSet,
) -> None:
    matched_rule = check_connection_rules(
        client=client,
        ruleset=ruleset,
    )
    if matched_rule and matched_rule.action is RuleAction.BLOCK:
        raise SocksRulesetError(client=client, rule=matched_rule)


def check_proxy_rules(
    client: ClientModel,
    ruleset: RuleSet,
    request_to: Union[IPv4Address, IPv6Address],
    user: Optional[str] = None,
) -> Optional[ProxyRule]:
    for rule in reversed(ruleset.proxy):
        if not isinstance(rule, ProxyRule):
            continue
        if rule.user and rule.user != user:
            continue
        if check_matched_from(client, rule) and check_matched_to(request_to, rule):
            return rule
    return None
