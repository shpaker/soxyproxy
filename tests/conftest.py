from asyncio import gather, open_connection
from logging import basicConfig, getLogger
from typing import Callable, Optional

from httpx_socks import AsyncProxyTransport
from passlib.apache import HtpasswdFile
from pytest import fixture, mark

from soxyproxy.models.ruleset import RuleSet
from soxyproxy.socks4 import Socks4
from soxyproxy.socks5 import Socks5

logger = getLogger(__name__)
basicConfig(level="DEBUG")
TEST_SERVER_PORT = 8888


@fixture()
def proxy_transport() -> Callable[[str, Optional[str], Optional[str]], AsyncProxyTransport]:
    def func(
        protocol: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = TEST_SERVER_PORT,
    ):
        auth_str = f"{username}:{password}@" if username else ""
        return AsyncProxyTransport.from_url(f"{protocol}://{auth_str}127.0.0.1:{port}")

    return func


@mark.asyncio
@fixture()
async def run_socks4_server():
    proxy = Socks4()
    pending = gather(
        proxy.serve(
            host="0.0.0.0",
            port=TEST_SERVER_PORT,
        ),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks5_server():
    proxy = Socks5()
    pending = gather(
        proxy.serve(
            host="0.0.0.0",
            port=TEST_SERVER_PORT,
        ),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks5_auth_server():
    htpasswd = HtpasswdFile()
    htpasswd.set_password("someuser", "mypass")
    htpasswd.set_password("blocked", "mypass")
    proxy = Socks5(authers=(htpasswd.check_password,))
    pending = gather(
        proxy.serve(
            host="0.0.0.0",
            port=TEST_SERVER_PORT,
        ),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks4_server_with_client_block_rule():
    client_rule_dict = {"action": "block", "from": "0.0.0.0/0"}
    ruleset = RuleSet(connection=(client_rule_dict,))
    proxy = Socks4(ruleset=ruleset)
    pending = gather(
        proxy.serve(host="0.0.0.0", port=TEST_SERVER_PORT),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks4_server_with_proxy_block_rule():
    proxy_rule_dict = {"action": "block", "to": "8.8.8.8"}
    ruleset = RuleSet(proxy=(proxy_rule_dict,))
    proxy = Socks4(ruleset=ruleset)
    pending = gather(
        proxy.serve(host="0.0.0.0", port=TEST_SERVER_PORT),
    )
    yield
    pending.cancel()


@mark.asyncio
@fixture()
async def run_socks5_server_with_proxy_block_rule():
    proxy_rule_dict_1 = {"action": "block", "user": "blocked"}
    proxy_rule_dict_2 = {"action": "block", "user": "someuser", "to": "8.8.8.8"}
    htpasswd = HtpasswdFile()
    htpasswd.set_password("someuser", "mypass")
    htpasswd.set_password("blocked", "mypass")
    ruleset = RuleSet(
        proxy=(
            proxy_rule_dict_1,
            proxy_rule_dict_2,
        )
    )
    proxy = Socks5(authers=(htpasswd.check_password,), ruleset=ruleset)
    pending = gather(
        proxy.serve(host="0.0.0.0", port=TEST_SERVER_PORT),
    )
    yield
    pending.cancel()


@fixture()
def send_data():
    async def func(data: bytes) -> bytes:
        reader, writer = await open_connection("127.0.0.1", TEST_SERVER_PORT)
        writer.write(data)
        await writer.drain()
        data = await reader.read(100)
        writer.close()
        await writer.wait_closed()
        return data

    return func
