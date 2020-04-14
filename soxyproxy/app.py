import asyncio
import logging
from typing import Optional, Coroutine

from typer import Option, Typer, echo, BadParameter

from soxyproxy import Socks, Socks4, Socks5

app = Typer()
logging.basicConfig(format='[%(asctime)s] %(levelname)-8s %(message)s', level=logging.DEBUG)

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 1080


@app.command()
def socks4(host: str = Option(DEFAULT_HOST), port: int = Option(DEFAULT_PORT)) -> None:
    server = Socks4()
    start_server(server=server, host=host, port=port)


@app.command()
def socks5(host: str = Option(DEFAULT_HOST),
           port: int = Option(DEFAULT_PORT),
           username: Optional[str] = Option(None),
           password: Optional[str] = Option(None)) -> None:

    if username and not password or not username and password:
        raise BadParameter('please, specify username and password')

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
