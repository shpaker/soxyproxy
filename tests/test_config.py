import io
from pathlib import Path

import pytest

from soxy import SystemResolver
from soxy._config import Config, ConfigError
from soxy._socks import Socks4, Socks5
from soxy._tcp import TcpTransport


def test_load_valid_config() -> None:
    config_data = """
    [proxy]
    protocol = "socks5"
    transport = "tcp"

    [transport]
    port = 1080

    [ruleset]
    connecting = { allow = [], block = [] }
    proxying = { allow = [], block = [] }
    """

    config = Config.load(io.BytesIO(config_data.encode()))
    assert isinstance(config.transport, TcpTransport)
    assert isinstance(config.socks, Socks5)


def test_load_invalid_toml() -> None:
    with pytest.raises(ConfigError, match='Failed to parse configuration'):
        Config.load(io.BytesIO(b'invalid toml'))


def test_from_path_missing_file() -> None:
    with pytest.raises(ConfigError, match='Configuration file not found'):
        Config.from_path(Path('/nonexistent/path'))


def test_socks_protocols() -> None:
    config_data = """
    [proxy]
    protocol = "socks4"
    [transport]
    port = 1080
    [ruleset]
    connecting = { allow = [], block = [] }
    proxying = { allow = [], block = [] }
    """
    config = Config.load(io.BytesIO(config_data.encode()))
    assert isinstance(config.socks, Socks4)

    config_data = config_data.replace('socks4', 'socks5')
    config = Config.load(io.BytesIO(config_data.encode()))
    assert isinstance(config.socks, Socks5)


def test_invalid_socks_protocol() -> None:
    config_data = """
    [proxy]
    protocol = "invalid"
    [transport]
    port = 1080
    [ruleset]
    connecting = { allow = [], block = [] }
    proxying = { allow = [], block = [] }
    """
    config = Config.load(io.BytesIO(config_data.encode()))
    with pytest.raises(ConfigError, match='Unsupported SOCKS protocol'):
        _ = config.socks


def test_invalid_transport() -> None:
    config_data = """
    [proxy]
    transport = "invalid"
    [transport]
    port = 1080
    [ruleset]
    connecting = { allow = [], block = [] }
    proxying = { allow = [], block = [] }
    """
    config = Config.load(io.BytesIO(config_data.encode()))
    with pytest.raises(ConfigError, match='Unsupported transport protocol'):
        _ = config.transport


def test_missing_ruleset() -> None:
    config_data = """
    [proxy]
    protocol = "socks5"
    [transport]
    port = 1080
    """
    with pytest.raises(ConfigError, match='Missing ruleset configuration'):
        Config.load(io.BytesIO(config_data.encode()))


def test_invalid_proxy_section() -> None:
    config_data = """
    proxy = "invalid"
    [transport]
    port = 1080
    [ruleset]
    connecting = { allow = [], block = [] }
    """
    with pytest.raises(ConfigError, match='Invalid proxy configuration'):
        Config.load(io.BytesIO(config_data.encode()))


_RESOLVER_CONFIG = """
[proxy]
protocol = "socks5h"
{extra}
[transport]
port = 1080
[ruleset]
connecting = {{ allow = [], block = [] }}
proxying = {{ allow = [], block = [] }}
"""


def test_resolver_timeout() -> None:
    config = Config.load(io.BytesIO(_RESOLVER_CONFIG.format(extra='resolve_timeout = 5').encode()))
    resolver = config._create_resolver()  # noqa: SLF001
    assert isinstance(resolver, SystemResolver)
    assert resolver._timeout == 5  # noqa: SLF001, PLR2004


def test_resolver_default_timeout() -> None:
    config = Config.load(io.BytesIO(_RESOLVER_CONFIG.format(extra='').encode()))
    resolver = config._create_resolver()  # noqa: SLF001
    assert isinstance(resolver, SystemResolver)
    assert resolver._timeout == 10  # noqa: SLF001, PLR2004


@pytest.mark.parametrize('value', ['0', '-1', '"5"', 'true'])
def test_resolver_invalid_timeout(value: str) -> None:
    config = Config.load(io.BytesIO(_RESOLVER_CONFIG.format(extra=f'resolve_timeout = {value}').encode()))
    with pytest.raises(ConfigError, match='resolve_timeout'):
        config.socks  # noqa: B018
