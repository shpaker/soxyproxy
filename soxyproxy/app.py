import asyncio
import logging
from typing import Optional

from environs import Env
from typer import Option, Typer, echo, BadParameter

from soxyproxy import Socks4, Socks5
from soxyproxy.protocols import Protocols

logging.basicConfig(format='[%(asctime)s] %(levelname)-8s %(message)s', level=logging.DEBUG)

app = Typer()

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 1080


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
    env_proxy_protocol: str = env.str('PROXY_PROTOCOL', None)

    if env_proxy_protocol is None:
        app()
        return

    echo('Configuration with environment variables')

    protocol = Protocols[env_proxy_protocol.upper()]

    host = env.str('PROXY_HOST', DEFAULT_HOST)
    port = env.int('PROXY_PORT', DEFAULT_PORT)
    user = env.str('PROXY_USER', None)
    password = env.str('PROXY_PASSWORD', None)

    proxy = Socks4() if protocol is Protocols.SOCKS4 else Socks5(user, password)
    asyncio.run(proxy.run(host, port))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        echo('Server stopped')
