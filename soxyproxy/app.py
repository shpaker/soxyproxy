import asyncio
import logging
from enum import Enum, unique, auto
from typing import Optional

from environs import Env
from typer import Option, Typer, echo, BadParameter

from soxyproxy import Socks4, Socks5
from soxyproxy.protocols import Protocols

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 1080
LOG_FORMAT = '[%(asctime)s] %(levelname)-8s %(message)s'

logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
app = Typer()


@unique
class EnvConfigVars(Enum):
    PROXY_PROTOCOL = auto()
    PROXY_HOST = auto()
    PROXY_PORT = auto()
    PROXY_USER = auto()
    PROXY_PASSWORD = auto()


@app.command()
def socks4(host: str = Option(DEFAULT_HOST), port: int = Option(DEFAULT_PORT)) -> None:
    proxy = Socks4()
    asyncio.run(proxy.run(host=host, port=port))


@app.command()
def socks5(host: str = Option(DEFAULT_HOST),
           port: int = Option(DEFAULT_PORT),
           username: Optional[str] = Option(None),
           password: Optional[str] = Option(None)) -> None:
    try:
        proxy = Socks5(username=username, password=password)
    except:
        raise BadParameter('please, specify username and password')

    asyncio.run(proxy.run(host=host, port=port))


def main():
    env = Env()
    env_proxy_protocol: Optional[str] = env.str(EnvConfigVars.PROXY_PROTOCOL.name, None)

    if env_proxy_protocol is None:
        app()
        return

    protocol = Protocols[env_proxy_protocol.upper()]

    host = env.str(EnvConfigVars.PROXY_HOST.name, DEFAULT_HOST)
    port = env.int(EnvConfigVars.PROXY_PORT.name, DEFAULT_PORT)
    user = env.str(EnvConfigVars.PROXY_USER.name, None)
    password = env.str(EnvConfigVars.PROXY_PASSWORD.name, None)

    proxy = Socks4() if protocol is Protocols.SOCKS4 else Socks5(user, password)
    asyncio.run(proxy.run(host, port))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        echo('Server stopped')
