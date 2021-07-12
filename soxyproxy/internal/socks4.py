from logging import getLogger

from soxyproxy import RuleSet
from soxyproxy.connections import SocksConnection
from soxyproxy.consts import Socks4Reply
from soxyproxy.exceptions import SocksRulesetError
from soxyproxy.internal.ruleset import check_proxy_rules
from soxyproxy.models.ruleset import RuleAction
from soxyproxy.models.socks4 import connection

logger = getLogger(__name__)


def socks4_raise_for_proxy_ruleset(
    client: SocksConnection,
    ruleset: RuleSet,
    request: connection.RequestModel,
) -> None:
    matched_rule = check_proxy_rules(
        client=client,
        ruleset=ruleset,
        request_to=request.address,
    )
    if not matched_rule or matched_rule.action is RuleAction.PASS:
        return None
    response = connection.ResponseModel(
        reply=Socks4Reply.REJECTED,
        address=request.address,
        port=request.port,
    )
    client.writer.write(response.dump())
    logger.warning(f"{client} <- {request.json()}")
    raise SocksRulesetError(client=client, rule=matched_rule)
