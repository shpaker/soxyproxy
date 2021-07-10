from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from typing import Optional, Union

from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import RuleSet, ClientRule, RuleAction, ProxyRule

DEFAULT_RULE_ACTION = RuleAction.PASS


def check_matched_from(
    client: ClientModel,
    rule: Union[ClientRule, ProxyRule],
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
        return False
    from_is_network = isinstance(rule.from_address, (IPv4Network, IPv6Network))
    if from_is_network and request_to in rule.to_address:  # type: ignore
        return True
    if not from_is_network and rule.to_address == request_to:
        return True
    return False


def check_client_rules_action(
    ruleset: RuleSet,
    client: ClientModel,
) -> Optional[ClientRule]:
    matched_rule: Optional[ClientRule] = None
    for rule in ruleset.__root__:
        if not isinstance(rule, ClientRule):
            continue
        if check_matched_from(client, rule):
            matched_rule = rule
    return matched_rule


def check_proxy_rules_action(
    ruleset: RuleSet,
    client: ClientModel,
    request_to: Union[IPv4Address, IPv6Address],
    user: Optional[str] = None,
) -> Optional[ProxyRule]:
    matched_rule: Optional[ProxyRule] = None
    for rule in ruleset.__root__:
        if not isinstance(rule, ProxyRule):
            continue
        if check_matched_from(client, rule) and check_matched_to(request_to, rule):
            if rule.user and rule.user != user:
                continue
            matched_rule = rule
    return matched_rule
