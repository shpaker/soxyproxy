from ipaddress import IPv4Network, IPv6Network

from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import RuleSet, ClientRule, RuleAction


def check_block_by_client_rules(
    ruleset: RuleSet,
    client: ClientModel,
) -> bool:
    for rule in ruleset.__root__:
        if not isinstance(rule, ClientRule):
            continue
        from_is_network = isinstance(rule.from_address, (IPv4Network, IPv6Network))
        if from_is_network and client.host in rule.from_address:  # type: ignore
            if rule.action is RuleAction.BLOCK:
                return True
    return False
