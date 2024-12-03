# soxy.Proxy

Асинхронная socks4/4a/5/5h прокся, написанная от скуки в целях самообучения, ~~без единного гвоздя~~ без использования внешних зависимостей

## install

```shell
pip install soxyproxy
```

## Usage

### Используем из кода

```python
import asyncio
from ipaddress import IPv4Address, IPv4Network

import soxy


async def async_main() -> None:
  async with soxy.Proxy(
    protocol=soxy.Socks5(),
    transport=soxy.TcpTransport(),
    ruleset=soxy.Ruleset(
      allow_rules=[
        soxy.Rule(
          from_addresses=IPv4Address("127.0.0.1"),
          to_addresses=IPv4Network("0.0.0.0/0"),
        ),
      ],
    ),
  ) as app:
    await app.serve_forever()


if __name__ == "__main__":
  asyncio.run(async_main())
```

### В качестве инструмента коммандной строки

- пишем конфиг следующего вида и сохарняем в `socks5.toml`:

  ```toml
  [proxy]
  protocol = "socks5"
  transport = "tcp"
  
  [transport]
  host = "127.0.0.1"
  port = 1080
  
  [[ruleset.allow]]
  from = "127.0.0.1"
  to = "0.0.0.0/0"
  
  [[ruleset.allow]]
  from = "192.168.0.2"
  to = "0.0.0.0/0"
  ```

- запускаем сервер:

  ```shell
  soxyproxy socks5.toml logs.txt 
  ```
  
  если хочется чтоб логи летели в терминал, то параметр с файлом логов можно не указывать и оставить просто `soxyproxy socks5.toml` 
