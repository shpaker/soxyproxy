import asyncio
import logging
from typing import Optional, Coroutine

from typer import Option, Typer, echo, BadParameter

from soxyproxy import Socks5
from soxyproxy.socks import Socks

app = Typer()
logging.basicConfig(format='[%(asctime)s] %(levelname)-8s %(message)s', level=logging.DEBUG)

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 1080


@app.command()
def socks4():
    print('4')


@app.command()
def socks4a():
    print('4a')


@app.command()
def socks5(host: str = Option(DEFAULT_HOST),
           port: int = Option(DEFAULT_PORT),
           username: Optional[str] = Option(None),
           password: Optional[str] = Option(None)) -> None:

    if username and not password:
        raise BadParameter('empty password not allowed', param_hint='--password')

    server = Socks5(username=username, password=password)

    start_server(server=server, host=host, port=port)


def start_server(server: Socks, host: str, port: int) -> None:

    server_coroutine: Coroutine[str, int] = server.run(host=host, port=port)

    echo(f'Start SOCKS{server.version.value} server at {host}:{port}')

    try:
        asyncio.run(server_coroutine)
    except KeyboardInterrupt:
        echo('Server stopped')


if __name__ == "__main__":
    app()
