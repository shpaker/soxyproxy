import tomllib
import typing
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from soxyproxy._ruleset import Rule, Ruleset
from soxyproxy._socks4 import Socks4
from soxyproxy._socks5 import Socks5
from soxyproxy._tcp import TcpTransport
from soxyproxy._types import ProxyTransport

_DEFAULTS_PROXY_SECTION = {
    "protocol": "socks5",
    "transport": "tcp",
}


class Config:
    def __init__(
        self,
        data: dict[str, typing.Any],
    ) -> None:
        self._proxy_data = data.get("proxy", _DEFAULTS_PROXY_SECTION)
        self._transport_data = data.get("transport")
        try:
            self._ruleset_data = data["ruleset"]
        except ValueError as exc:
            msg = "ruleset configuration required"
            raise ValueError(msg) from exc

    @classmethod
    def load(
        cls,
        fh: typing.BinaryIO,
    ) -> typing.Self:
        return Config(tomllib.load(fh))

    @classmethod
    def from_path(
        cls,
        path: Path,
    ) -> typing.Self:
        with path.open("rb") as fh:
            return cls.load(fh)

    @property
    def transport(
        self,
    ) -> ProxyTransport:
        transport_cls = None
        match self._proxy_data.get("transport", _DEFAULTS_PROXY_SECTION["transport"]):
            case "tcp":
                transport_cls = TcpTransport
            case _:
                msg = "[proxy] specified unknown transport type"
                raise ValueError(msg)
        try:
            return transport_cls(**self._transport_data)
        except TypeError as exc:
            msg = "[transport] specified incorrect transport parameters"
            raise ValueError(msg) from exc

    def _make_rules(
        self,
        rules: list[dict[str, typing.Any]],
    ) -> list[Rule]:
        for rule_dict in rules:
            to_ = rule_dict.get("to")
            with suppress(ValueError):
                to_ = IPv4Network(to_)
            try:
                from_ = IPv4Address(rule_dict.get("from"))
            except ValueError:
                continue
            yield Rule(
                from_addresses=from_,
                to_addresses=to_,
            )

    @property
    def ruleset(
        self,
    ) -> Ruleset:
        return Ruleset(
            allow_rules=list(
                self._make_rules(self._ruleset_data.get("allow", [])),
            ),
            block_rules=list(
                self._make_rules(self._ruleset_data.get("block", [])),
            ),
        )

    @property
    def socks(
        self,
    ) -> Socks4 | Socks5:
        match self._proxy_data.get("protocol", _DEFAULTS_PROXY_SECTION["protocol"]):
            case "socks4":
                socks_cls = Socks4
            case "socks5":
                socks_cls = Socks5
            case _:
                msg = "[proxy] specified unknown protocol type"
                raise ValueError(msg)
        return socks_cls()
