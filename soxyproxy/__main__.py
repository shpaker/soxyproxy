import asyncio
import logging
from pathlib import Path
from typing import Optional, Union

from passlib.apache import HtpasswdFile
from typer import Option, Typer

from soxyproxy import RuleSet, Socks4, Socks5

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
    asyncio.run(proxy.serve(host=host, port=port))


@app.command()
def socks4(
    host: str = Option(
        DEFAULT_HOST,
    ),
    port: int = Option(
        DEFAULT_PORT,
    ),
    ruleset: Optional[Path] = Option(
        None,
        exists=True,
        dir_okay=False,
        file_okay=True,
    ),
) -> None:
    ruleset_model = RuleSet.from_file(ruleset) if ruleset else RuleSet()
    proxy = Socks4(ruleset=ruleset_model)
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
        help="Apache-Like Authentication (.htpasswd)",
    ),
    ruleset: Optional[Path] = Option(
        None,
        exists=True,
        dir_okay=False,
        file_okay=True,
    ),
) -> None:
    authers = list()
    ruleset_model = RuleSet.from_file(ruleset) if ruleset else RuleSet()
    if passwords:
        htpasswd = HtpasswdFile(passwords)
        authers.append(htpasswd.check_password)
    proxy = Socks5(ruleset=ruleset_model, authers=authers)
    start_server(proxy, host, port)


if __name__ == "__main__":
    app()
