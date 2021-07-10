import asyncio
import logging
from pathlib import Path
from typing import Union, Optional

from passlib.apache import HtpasswdFile
from typer import Option, Typer

from soxyproxy.socks4 import Socks4
from soxyproxy.socks5 import Socks5

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1080
logging.basicConfig(
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    level=logging.DEBUG,
)
app = Typer()


def start_server(
    proxy: Union[
        Socks4,
        Socks5,
    ],
    host: str,
    port: int,
) -> None:
    logging.info(f"Start serving {host}:{port}")
    asyncio.run(proxy.run(host=host, port=port))


@app.command()
def socks4(
    host: str = Option(
        DEFAULT_HOST,
    ),
    port: int = Option(
        DEFAULT_PORT,
    ),
) -> None:
    proxy = Socks4()
    start_server(proxy, host, port)


@app.command()
def socks5(
    host: str = Option(
        DEFAULT_HOST,
    ),
    port: int = Option(
        DEFAULT_PORT,
    ),
    passwords: Optional[Path] = Option(
        None,
        exists=True,
        dir_okay=False,
        file_okay=True,
        help="Apache-Like Authentication (htpasswd)",
    ),
) -> None:
    auther = None
    if passwords:
        htpasswd = HtpasswdFile(passwords)
        auther = htpasswd.check_password
    proxy = Socks5(auther=auther)
    start_server(proxy, host, port)


if __name__ == "__main__":
    app()
