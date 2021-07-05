import asyncio
import logging
from typing import Union

from typer import Option, Typer  # pylint: disable=wrong-import-order

from soxyproxy.socks4 import Socks4

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1080
logging.basicConfig(
    format="[%(asctime)s] %(levelname)-8s %(message)s", level=logging.DEBUG
)
app = Typer()


def start_server(
    proxy: Union[Socks4],
    host: str,
    port: int,
) -> None:
    logging.info(f"Start serving {host}:{port}")
    asyncio.run(proxy.run(host=host, port=port))


@app.command()
def socks4(
    host: str = Option(DEFAULT_HOST),
    port: int = Option(DEFAULT_PORT),
) -> None:
    proxy = Socks4()
    start_server(proxy, host, port)


# @app.command()
# def socks5(
#     host: str = Option(DEFAULT_HOST),
#     port: int = Option(DEFAULT_PORT),
#     username: Optional[str] = Option(None),
#     password: Optional[str] = Option(None),
# ) -> None:
#     try:
#         proxy = Socks5(username=username, password=password)
#     except KeyError as err:
#         raise BadParameter("Authentication credentials required") from err
#     start_server(proxy, host, port)
