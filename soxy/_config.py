import asyncio
import tomllib
import typing
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from socket import gethostbyname

from soxy._errors import ConfigError
from soxy._ruleset import ConnectingRule, ProxyingRule, Ruleset
from soxy._socks import Socks4, Socks5
from soxy._tcp import TcpTransport
from soxy._types import (
    ProxySocks,
    Resolver,
    Socks4Auther,
    Socks5Auther,
    Transport,
)

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
        if not isinstance(self._proxy_data, dict):
            msg = 'Invalid proxy configuration'
            raise ConfigError('proxy', msg)

        if not isinstance(transport_data := data.get('transport'), dict):
            msg = 'Invalid transport configuration'
            raise ConfigError('transport', msg)
        self._transport_data = transport_data

        try:
            self._ruleset_data = data['ruleset']
            if not isinstance(self._ruleset_data, dict):
                msg = 'Invalid ruleset configuration'
                raise ConfigError('ruleset', msg)
        except KeyError as exc:
            msg = 'Missing ruleset configuration'
            raise ConfigError('ruleset', msg) from exc

    @classmethod
    def load(
        cls,
        fh: typing.BinaryIO,
    ) -> typing.Self:
        try:
            data = tomllib.load(fh)
            if not isinstance(data, dict):
                msg = 'Invalid configuration format'
                raise ConfigError('config', msg)
            return cls(data)
        except tomllib.TOMLDecodeError as exc:
            msg = 'Failed to parse configuration'
            raise ConfigError('config', msg) from exc

    @classmethod
    def from_path(
        cls,
        path: Path,
    ) -> typing.Self:
        if not path.is_file():
            msg = f'Configuration file not found: {path}'
            raise ConfigError('config', msg)
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
                msg = 'Unsupported transport protocol'
                raise ConfigError('transport', msg)
        try:
            return transport_cls(**self._transport_data)
        except TypeError as exc:
            msg = 'Invalid transport configuration'
            raise ConfigError('transport', msg) from exc

    def _make_connecting_rules(
        self,
        rules: list[dict[str, typing.Any]],
    ) -> typing.Generator[ConnectingRule, None, None]:
        for rule_dict in rules:
            from_ = None
            from_str = rule_dict.get('from')
            if not from_str:
                continue
            try:
                from_ = IPv4Address(from_str)
            except (ValueError, TypeError):
                try:
                    from_ = IPv4Network(from_str)
                except (ValueError, TypeError):
                    try:
                        from_ = IPv6Address(from_str)
                    except (ValueError, TypeError):
                        try:
                            from_ = IPv6Network(from_str)
                        except (ValueError, TypeError):
                            continue
            if not isinstance(
                from_,
                IPv4Address | IPv6Address | IPv4Network | IPv6Network,
            ):
                continue
            yield ConnectingRule(
                from_addresses=from_,
            )

    def _make_rules(
        self,
        rules: list[dict[str, typing.Any]],
    ) -> typing.Generator[ProxyingRule, None, None]:
        for rule_dict in rules:
            from_ = None
            from_str = rule_dict.get('from')
            if not from_str:
                continue
            try:
                from_ = IPv4Address(from_str)
            except (ValueError, TypeError):
                try:
                    from_ = IPv4Network(from_str)
                except (ValueError, TypeError):
                    try:
                        from_ = IPv6Address(from_str)
                    except (ValueError, TypeError):
                        try:
                            from_ = IPv6Network(from_str)
                        except (ValueError, TypeError):
                            continue
            if not isinstance(
                from_,
                IPv4Address | IPv6Address | IPv4Network | IPv6Network,
            ):
                continue
            to_ = rule_dict.get('to')
            if to_ is None:
                continue
            if isinstance(to_, str):
                to_parsed = None
                try:
                    to_parsed = IPv4Address(to_)
                except (ValueError, TypeError):
                    try:
                        to_parsed = IPv4Network(to_)
                    except (ValueError, TypeError):
                        try:
                            to_parsed = IPv6Address(to_)
                        except (ValueError, TypeError):
                            try:
                                to_parsed = IPv6Network(to_)
                            except (ValueError, TypeError):
                                pass
                if to_parsed is None:
                    to_ = to_
                else:
                    to_ = to_parsed
            if not isinstance(
                to_,
                IPv4Address | IPv6Address | IPv4Network | IPv6Network | str,
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
            allow_connecting_rules=list(
                self._make_connecting_rules(connecting.get('allow', [])),
            ),
            block_connecting_rules=list(
                self._make_connecting_rules(connecting.get('block', [])),
            ),
            allow_proxying_rules=list(
                self._make_rules(proxying.get('allow', [])),
            ),
            block_proxying_rules=list(
                self._make_rules(proxying.get('block', [])),
            ),
        )

    def _create_resolver(
        self,
    ) -> Resolver:
        """
        Create a resolver function using OS socket.gethostbyname.
        The blocking call is executed in a thread pool to avoid blocking the event loop.
        """
        async def resolver(domain_name: str) -> IPv4Address:
            ip_str = await asyncio.to_thread(gethostbyname, domain_name)
            return IPv4Address(ip_str)
        return resolver

    def _create_auther(
        self,
        protocol: str,
    ) -> Socks4Auther | Socks5Auther | None:
        """
        Create auther from configuration dictionary.
        Authentication is optional - if auth section is missing, returns None.
        """
        auth_data = self._proxy_data.get('auth')
        if not auth_data:
            return None

        if not isinstance(auth_data, dict):
            msg = 'Invalid auth configuration'
            raise ConfigError('proxy', msg)

        # For SOCKS5: username -> password mapping
        if protocol in ('socks5', 'socks5h'):
            def socks5_auther(username: str, password: str) -> bool:
                return auth_data.get(username) == password
            return socks5_auther

        # For SOCKS4: only username check (password not used)
        if protocol in ('socks4', 'socks4a'):
            def socks4_auther(username: str) -> bool:
                return username in auth_data
            return socks4_auther

        return None

    @property
    def socks(
        self,
    ) -> ProxySocks:
        protocol = self._proxy_data.get(
            'protocol',
            _DEFAULTS_PROXY_SECTION['protocol'],
        )

        # Determine if resolver is needed
        needs_resolver = protocol in ('socks4a', 'socks5h')
        resolver = self._create_resolver() if needs_resolver else None

        # Create auther if auth section is present (optional)
        auther = self._create_auther(protocol)

        socks_cls: type[Socks4] | type[Socks5]
        if protocol in ('socks4', 'socks4a'):
            socks_cls = Socks4
        elif protocol in ('socks5', 'socks5h'):
            socks_cls = Socks5
        else:
            msg = 'Unsupported SOCKS protocol'
            raise ConfigError('proxy', msg)

        return socks_cls(auther=auther, resolver=resolver)  # type: ignore[return-value]
