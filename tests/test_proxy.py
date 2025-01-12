from unittest.mock import AsyncMock, MagicMock

import pytest

from soxy import PackageError, ProtocolError
from soxy._proxy import Proxy
from soxy._ruleset import Ruleset
from soxy._types import Address, Connection, ProxySocks, Transport


@pytest.fixture
def proxy() -> Proxy:
    transport = MagicMock(spec=Transport)
    ruleset = Ruleset(allow_connecting_rules=[], allow_proxying_rules=[])
    protocol = MagicMock(spec=ProxySocks)
    return Proxy(transport=transport, ruleset=ruleset, protocol=protocol)


@pytest.mark.asyncio
async def test_proxy_aenter(proxy: Proxy) -> None:
    proxy._transport.__aenter__ = AsyncMock(return_value=MagicMock())
    server = await proxy.__aenter__()
    assert server is not None
    proxy._transport.__aenter__.assert_called_once()


@pytest.mark.asyncio
async def test_proxy_aexit(proxy: Proxy) -> None:
    proxy._transport.__aexit__ = AsyncMock()
    await proxy.__aexit__(None, None, None)
    proxy._transport.__aexit__.assert_called_once()


@pytest.mark.asyncio
async def test_on_client_connected_transport_cb(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    proxy._ruleset.should_allow_connecting = MagicMock(return_value=True)
    proxy._protocol = AsyncMock(return_value=(Address('127.0.0.1', 8080), 'example.com'))
    proxy._ruleset.should_allow_proxying = MagicMock(return_value=True)
    address = await proxy._on_client_connected_transport_cb(client)
    assert address is not None


@pytest.mark.asyncio
async def test_on_client_connected_transport_cb_reject(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    proxy._ruleset.should_allow_connecting = MagicMock(return_value=False)
    address = await proxy._on_client_connected_transport_cb(client)
    assert address is None


@pytest.mark.asyncio
async def test_on_client_connected_transport_cb_package_error(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    proxy._ruleset.should_allow_connecting = MagicMock(return_value=True)
    proxy._protocol = AsyncMock(side_effect=PackageError(data='error'))
    address = await proxy._on_client_connected_transport_cb(client)
    assert address is None


@pytest.mark.asyncio
async def test_on_client_connected_transport_cb_protocol_error(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    proxy._ruleset.should_allow_connecting = MagicMock(return_value=True)
    proxy._protocol = AsyncMock(side_effect=ProtocolError())
    address = await proxy._on_client_connected_transport_cb(client)
    assert address is None


@pytest.mark.asyncio
async def test_start_messaging_transport_cb(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    remote = MagicMock(spec=Connection)
    proxy._protocol.success = AsyncMock()
    await proxy._start_messaging_transport_cb(client, remote)
    proxy._protocol.success.assert_called_once_with(client=client, destination=remote.address)


@pytest.mark.asyncio
async def test_on_remote_connection_unreachable_cb(proxy: Proxy) -> None:
    client = MagicMock(spec=Connection)
    destination = Address('127.0.0.1', 8080)
    proxy._protocol.target_unreachable = AsyncMock()
    await proxy._on_remote_connection_unreachable_cb(client, destination)
    proxy._protocol.target_unreachable.assert_called_once_with(client=client, destination=destination)
