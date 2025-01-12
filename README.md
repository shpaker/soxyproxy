# 💃 soxy👯‍♀️proxy 🕺

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PyPI](https://img.shields.io/pypi/v/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)
[![PyPI](https://img.shields.io/pypi/dm/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)

soxyproxy is an asynchronous proxy server supporting socks4, socks4a, socks5, and socks5h protocols. It is designed for educational purposes and built without any external dependencies, making it a pure Python implementation.

This project is actively developed on a periodic basis and is maintained as a hobby. Contributions and feedback are welcome. Feel free to reach out via my Telegram account [@shpaker](https://t.me/shpaker).

## 🛩️ Installation

```shell
pip install soxyproxy
```

## 🫶🏼 Getting Started

### 👨‍💻 Running from Code

```python
import asyncio
import logging
from ipaddress import IPv4Address, IPv4Network
from socket import gethostbyname

import soxy

logging.basicConfig(level=logging.INFO)


def auther(username: str, password: str) -> bool:
    return username == "top" and password == "secret"


def resolver(domain_name: str) -> IPv4Address:
    return IPv4Address(gethostbyname(domain_name))


async def main() -> None:
    async with soxy.Proxy(
        protocol=soxy.Socks5(
            auther=auther,
            resolver=resolver,  # if resolver is not provided, 5h (and 4a in case of Socks4) won't work
        ),
        transport=soxy.TcpTransport(),
        ruleset=soxy.Ruleset(
            allow_connecting_rules=[
                # at least one allowing rule for connecting is required
                soxy.ConnectingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                )
            ],
            allow_proxying_rules=[
                # at least one allowing rule for proxying is required
                soxy.ProxyingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                    to_addresses=IPv4Network("0.0.0.0/0"),
                ),
            ],
        ),
    ) as app:
        await app.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

#### Testing with curl

socks5:

```shell
curl -x "socks5://top:secret@127.0.0.1:1080" https://google.com -v
```

socks5h:

```shell
curl -x "socks5h://top:secret@127.0.0.1:1080" https://google.com -v
```

### 👟 Command Line Tool

It's very simple here.

#### Write a config like the following and save it as `socks5.toml`:

```toml
[proxy]
protocol = "socks5"
transport = "tcp"
clients_from = [
  '0.0.0.0/0',
]

[transport]
host = '127.0.0.1'
port = 1080

[[ruleset.connecting.allow]]
from = '127.0.0.1'

[[ruleset.proxying.allow]]
from = "127.0.0.1"
to = "0.0.0.0/0"
```

#### Start the server:

```shell
soxy socks5.toml logs.txt 
```

If you want the logs to be printed to the terminal, you can omit the log file parameter and just use `soxyproxy socks5.toml`.

## Key Features

- **Asynchronous**: Built with asyncio for high performance.
- **No External Dependencies**: Pure Python implementation.
- **Supports Multiple Protocols**: socks4, socks4a, socks5, socks5h.
- **Customizable**: Easily extendable with custom authentication and resolution logic.
- **Command Line Interface**: Simple to use as a CLI tool with configuration files.

## Additional Examples

### Running with Custom Authentication

```python
def custom_auther(username: str, password: str) -> bool:
    return username == "admin" and password == "admin123"

async def main() -> None:
    async with soxy.Proxy(
        protocol=soxy.Socks5(
            auther=custom_auther,
            resolver=resolver,
        ),
        transport=soxy.TcpTransport(),
        ruleset=soxy.Ruleset(
            allow_connecting_rules=[
                soxy.ConnectingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                )
            ],
            allow_proxying_rules=[
                soxy.ProxyingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                    to_addresses=IPv4Network("0.0.0.0/0"),
                ),
            ],
        ),
    ) as app:
        await app.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
```

### Running with Custom Resolver

```python
def custom_resolver(domain_name: str) -> IPv4Address:
    # Custom logic to resolve domain names
    return IPv4Address("8.8.8.8")

async def main() -> None:
    async with soxy.Proxy(
        protocol=soxy.Socks5(
            auther=auther,
            resolver=custom_resolver,
        ),
        transport=soxy.TcpTransport(),
        ruleset=soxy.Ruleset(
            allow_connecting_rules=[
                soxy.ConnectingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                )
            ],
            allow_proxying_rules=[
                soxy.ProxyingRule(
                    from_addresses=IPv4Address("127.0.0.1"),
                    to_addresses=IPv4Network("0.0.0.0/0"),
                ),
            ],
        ),
    ) as app:
        await app.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
```
