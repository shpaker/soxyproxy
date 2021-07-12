from logging import getLogger
from typing import Optional

from soxyproxy.connections import SocksConnection
from soxyproxy.consts import Socks5ConnectionReply
from soxyproxy.exceptions import SocksRulesetError
from soxyproxy.internal.ruleset import check_proxy_rules
from soxyproxy.models.ruleset import RuleAction, RuleSet
from soxyproxy.models.socks5 import connection

logger = getLogger(__name__)


def socks5_raise_for_proxy_ruleset(
    client: SocksConnection,
    ruleset: RuleSet,
    request: connection.RequestModel,
    user: Optional[str],
) -> None:
    matched_rule = check_proxy_rules(
        client=client,
        ruleset=ruleset,
        request_to=request.address,
        user=user,
    )
    if not matched_rule or matched_rule.action is RuleAction.PASS:
        return None
    response = connection.ResponseModel(
        reply=Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET,
        address=request.address,
        port=request.port,
    )
    client.writer.write(response.dump())
    logger.warning(f"{client} <- {request.json()}")
    raise SocksRulesetError(client=client, rule=matched_rule)
