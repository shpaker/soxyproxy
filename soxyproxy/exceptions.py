from typing import Union

from soxyproxy.connections import SocksConnection
from soxyproxy.models.ruleset import ConnectionRule, ProxyRule


class SocksError(Exception):
    def __init__(
        self,
        client: SocksConnection,
        message: str = "",
    ) -> None:
        super().__init__(message)
        self.client = client


class SocksRulesetError(SocksError):
    def __init__(
        self,
        client: SocksConnection,
        rule: Union[
            ConnectionRule,
            ProxyRule,
        ],
    ) -> None:
        self.rule = rule
        rule_type = "proxy" if isinstance(rule, ProxyRule) else "connection"
        super().__init__(client, f"{client} ! blocked by {rule_type}-rule: {rule.json()}")


class SocksPackageError(SocksError):
    def __init__(
        self,
        client: SocksConnection,
        raw: bytes,
    ):
        self.raw = raw
        super().__init__(client, f"{client} ! package error: {str(raw)}")


class SocksConnectionError(SocksError):
    def __init__(
        self,
        client: SocksConnection,
        host: str,
        port: int,
    ):
        self.host = host
        self.port = port
        super().__init__(client, f"{client} ! connection error: {host}:{port}")
