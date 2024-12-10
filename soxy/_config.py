import tomllib
import typing
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path

from soxy._errors import ConfigError
from soxy._ruleset import ProxyingRule, Ruleset
from soxy._socks import Socks4, Socks5
from soxy._tcp import TcpTransport
from soxy._types import ProxySocks, Transport

_DEFAULTS_PROXY_SECTION = {
    'protocol': 'socks5',
    'transport': 'tcp',
}


class Config:
    def __init__(
        self,
        data: dict[str, typing.Any],
    ) -> None:
        self._proxy_data = data.get('proxy', _DEFAULTS_PROXY_SECTION)
        if not isinstance(transport_data := data.get('transport'), dict):
            msg = 'transport'
            raise ConfigError(msg)
        self._transport_data = transport_data
        try:
            self._ruleset_data = data['ruleset']
        except ValueError as exc:
            msg = 'ruleset'
            raise ConfigError(msg) from exc

    @classmethod
    def load(
        cls,
        fh: typing.BinaryIO,
    ) -> typing.Self:
        return cls(tomllib.load(fh))

    @classmethod
    def from_path(
        cls,
        path: Path,
    ) -> typing.Self:
        with path.open('rb') as fh:
            return cls.load(fh)

    @property
    def transport(
        self,
    ) -> Transport:
        match self._proxy_data.get(
            'transport',
            _DEFAULTS_PROXY_SECTION['transport'],
        ):
            case 'tcp':
                transport_cls = TcpTransport
            case _:
                msg = 'transport'
                raise ConfigError(msg)
        try:
            return transport_cls(**self._transport_data)
        except TypeError as exc:
            msg = 'transport'
            raise ConfigError(msg) from exc

    def _make_rules(
        self,
        rules: list[dict[str, typing.Any]],
    ) -> typing.Generator[ProxyingRule, None, None]:
        for rule_dict in rules:
            to_ = rule_dict.get('to')
            with suppress(ValueError):
                to_ = IPv4Network(to_)
            try:
                from_ = IPv4Address(rule_dict.get('from'))
            except ValueError:
                continue
            if not (
                isinstance(to_, IPv4Address | IPv6Address | IPv4Network | IPv6Network)
                and isinstance(
                    from_,
                    IPv4Address | IPv6Address | IPv4Network | IPv6Network | str,
                )
            ):
                continue
            yield ProxyingRule(
                from_addresses=from_,
                to_addresses=to_,
            )

    @property
    def ruleset(
        self,
    ) -> Ruleset:
        connecting = self._ruleset_data.get('connecting', {})
        proxying = self._ruleset_data.get('proxying', {})
        return Ruleset(
            allow_connecting_rules=list(connecting.get('allow', [])),
            block_connecting_rules=list(connecting.get('block', [])),
            allow_proxying_rules=list(
                self._make_rules(proxying.get('allow', [])),
            ),
            block_proxying_rules=list(
                self._make_rules(proxying.get('block', [])),
            ),
        )

    @property
    def socks(
        self,
    ) -> ProxySocks:
        socks_cls: type[Socks4] | type[Socks5]
        match self._proxy_data.get(
            'protocol',
            _DEFAULTS_PROXY_SECTION['protocol'],
        ):
            case 'socks4':
                socks_cls = Socks4
            case 'socks5':
                socks_cls = Socks5
            case _:
                msg = 'protocol'
                raise ConfigError(msg)
        return socks_cls()  # type: ignore[return-value]
