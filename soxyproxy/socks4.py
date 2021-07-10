import logging
from asyncio import StreamReader, StreamWriter, open_connection
from typing import Optional, Tuple

from soxyproxy.consts import Socks4Reply
from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import RuleAction
from soxyproxy.models.socks4 import connection
from soxyproxy.server import ServerBase
from soxyproxy.utils import check_proxy_rules_actions

logger = logging.getLogger(__name__)


class Socks4(ServerBase):
    async def connect(  # type: ignore
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        **kwargs,
    ) -> Optional[Tuple[StreamReader, StreamWriter]]:
        request_raw = await client_reader.read(512)
        client = ClientModel.from_writer(client_writer)
        try:
            request = connection.RequestModel.loads(request_raw)
            matched_rule = check_proxy_rules_actions(
                ruleset=self.ruleset,
                client=client,
                request_to=request.address,
            )
            if matched_rule and matched_rule.action is RuleAction.BLOCK:
                raise ConnectionError(
                    f"{client.host} ! connection blocked by rule: {matched_rule.json()}"
                )
            logger.debug(f"{client.host}:{client.port} -> {request.json()}")
            remote_reader, remote_writer = await open_connection(
                host=str(request.address),
                port=request.port,
            )
        except (ConnectionError, TimeoutError) as err:
            response = connection.ResponseModel(
                reply=Socks4Reply.REJECTED,
                address=connection.extract_address(request_raw),
                port=connection.extract_port(request_raw),
            )
            client_writer.write(response.dumps())
            raise ConnectionError(err) from err
        except Exception as err:
            raise ValueError(err) from err
        response = connection.ResponseModel(
            reply=Socks4Reply.GRANTED,
            address=request.address,
            port=request.port,
        )
        client_writer.write(response.dumps())
        return remote_reader, remote_writer
