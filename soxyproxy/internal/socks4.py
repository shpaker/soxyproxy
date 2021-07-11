import logging
from asyncio import StreamReader, StreamWriter, open_connection
from typing import Tuple

from soxyproxy import RuleSet
from soxyproxy.consts import Socks4Reply
from soxyproxy.exceptions import SocksConnectionError, SocksRulesetError
from soxyproxy.internal.ruleset import check_proxy_rules
from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import RuleAction
from soxyproxy.models.socks4 import connection

logger = logging.getLogger(__name__)


def check_ruleset(
    client: ClientModel,
    client_writer: StreamWriter,
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
    client_writer.write(response.dumps())
    logger.warning(f"{client} <- {request.json()}")
    raise SocksRulesetError(client=client, rule=matched_rule)


async def open_remote_connection(
    client: ClientModel,
    client_writer: StreamWriter,
    request: connection.RequestModel,
) -> Tuple[StreamReader, StreamWriter]:
    try:
        remote_reader, remote_writer = await open_connection(
            host=str(request.address),
            port=request.port,
        )
    except Exception as err:
        response = connection.ResponseModel(
            reply=Socks4Reply.REJECTED,
            address=request.address,
            port=request.port,
        )
        client_writer.write(response.dumps())
        logger.warning(f"{client} <- {request.json()}")
        raise SocksConnectionError(
            client=client,
            host=str(request.address),
            port=request.port,
        ) from err
    return remote_reader, remote_writer
