# 💃 soxy👯‍♀️proxy 🕺

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PyPI](https://img.shields.io/pypi/v/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)
[![PyPI](https://img.shields.io/pypi/dm/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)

Асинхронная socks4/4a/5/5h прокся, написанная от скуки в целях самообучения, ~~без единного гвоздя~~ без использования внешних зависимостей

Проект на этапе активной периодической разработки, и поддерживается по настроению.

Любые пожелания и прочие штуки можно мне писать в Телеграм-аккаунт [@shpaker](https://t.me/shpaker).  

## 🛩️ Install

```shell
pip install soxyproxy
```

## 🫶🏼  Пробуем

### 👨‍💻 Запускаем из кода

```python
import asyncio
import logging
from ipaddress import IPv4Address, IPv4Network
from socket import gethostbyname

import soxy

logging.basicConfig(level=logging.INFO)


def auther(
  username: str,
  password: str,
) -> bool:
  return username == "top" and password == "secret"


def resolver(
  domain_name: str,
) -> IPv4Address:
  return IPv4Address(gethostbyname(domain_name))


async def main() -> None:
  async with soxy.Proxy(
    protocol=soxy.Socks5(
      auther=auther,
      resolver=resolver,  # если резолвер не передать, то не будет работать 5h (и 4a в случае Socks4)
    ),
    transport=soxy.TcpTransport(),
    ruleset=soxy.Ruleset(
      allow_connecting_rules=[
        # необходимо хотя бы одно разрешающие правило для соединения
        soxy.ConnectingRule(
          from_addresses=IPv4Address("127.0.0.1"),
        )
      ],
      allow_proxying_rules=[
        # необходимо хотя бы одно разрешающие правило для проксирования
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

#### Проверить всегда можно курлом

socks5:

```shell
curl -x "socks5://top:secret@127.0.0.1:1080" https://google.ru -v
```

socks5h:

```shell
curl -x "socks5a://top:secret@127.0.0.1:1080" https://google.ru -v
```

### 👟  В качестве инструмента коммандной строки

Но тут все очень просто

#### пишем конфиг следующего вида и сохарняем в `socks5.toml`:

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

#### запускаем сервер:

```shell
soxy socks5.toml logs.txt 
```

если хочется чтоб логи летели в терминал, то параметр с файлом логов можно не указывать и оставить просто `soxyproxy socks5.toml` 
