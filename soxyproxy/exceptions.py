from typing import Union

from soxyproxy.models.client import ClientModel
from soxyproxy.models.ruleset import ConnectionRule, ProxyRule


class SocksError(Exception):
    ...


class SocksRulesetError(SocksError):
    def __init__(
        self,
        client: ClientModel,
        rule: Union[
            ConnectionRule,
            ProxyRule,
        ],
    ) -> None:
        self.client = client
        self.rule = rule
        rule_type = "proxy" if isinstance(rule, ProxyRule) else "connection"
        super().__init__(f"{client} ! blocked by {rule_type}-rule: {rule.json()}")


class SocksPackageError(SocksError):
    def __init__(
        self,
        client: ClientModel,
        raw: bytes,
    ):
        self.client = client
        self.raw = raw
        super().__init__(f"{client} ! package error: {str(raw)}")


class SocksConnectionError(SocksError):
    def __init__(
        self,
        client: ClientModel,
        host: str,
        port: int,
    ):
        self.client = client
        self.host = host
        self.port = port
        super().__init__(f"{client} ! connection error: {host}:{port}")
