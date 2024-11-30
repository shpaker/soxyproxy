# SoxyProxy

Асинхронная socks4/4a/5/5h прокся, написанная от скуки в целях самообучения, ~~без единного гвоздя~~ без использования внешних зависимостей

## install

```shell
pip install soxyproxy
```

## Usage

### Usage from code

```python
import asyncio
from ipaddress import IPv4Address, IPv4Network

from soxyproxy import TcpTransport, Proxy, Ruleset, Rule, Socks5


async def main() -> None:
  async with Proxy(
    protocol=Socks5(),
    transport=TcpTransport(),
    ruleset=Ruleset(
      allow_rules=[
        Rule(
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
