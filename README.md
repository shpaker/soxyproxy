# 💃 soxy👯‍♀️proxy 🕺

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![PyPI](https://img.shields.io/pypi/v/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)
[![PyPI](https://img.shields.io/pypi/dm/soxyproxy.svg)](https://pypi.python.org/pypi/soxyproxy)

An asynchronous proxy server written in pure Python, supporting SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h protocols. The project is designed for educational purposes and has no external dependencies.

This project is actively developed on a periodic basis and is maintained as a hobby. Contributions and feedback are welcome. Feel free to reach out via my Telegram account [@shpaker](https://t.me/shpaker).

## Features

- **Asynchronous**: Built with asyncio for high performance
- **No Dependencies**: Pure Python implementation without external libraries
- **Multiple Protocols**: Support for SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h
- **Flexible Configuration**: Custom authentication and domain resolution
- **Rule System**: Access control based on IP addresses and domains
- **CLI and API**: Use via command line or programmatic interface
- **Type Safety**: Full type hints support

## Requirements

- Python >= 3.14 (tested on 3.14 and 3.15)

## 🛩️ Installation

```bash
pip install soxyproxy
```

## 🫶🏼 Getting Started

### 👟 Command Line Tool

1. Create a configuration file `config.toml`:

```toml
[proxy]
protocol = "socks5"
transport = "tcp"

[transport]
host = "127.0.0.1"
port = 1080

[[ruleset.connecting.allow]]
from = "127.0.0.1"

[[ruleset.proxying.allow]]
from = "127.0.0.1"
to = "0.0.0.0/0"
```

2. Start the server:

```bash
# Logs to terminal
soxy config.toml

# Logs to file
soxy config.toml --logfile logs.txt
# or
soxy config.toml -l logs.txt
```

3. Test the connection:

```bash
# SOCKS5 (without authentication)
curl -x "socks5://127.0.0.1:1080" https://google.com -v

# SOCKS5h (domain is resolved on the proxy side, requires protocol = "socks5h")
curl -x "socks5h://127.0.0.1:1080" https://google.com -v

# SOCKS5 with authentication (requires the [proxy.auth] section, see below)
curl -x "socks5://alice:password123@127.0.0.1:1080" https://google.com -v
```

### 👨‍💻 Running from Code

```python
import asyncio
import logging
from ipaddress import IPv4Address, IPv4Network

import soxy

logging.basicConfig(level=logging.INFO)


def auther(username: str, password: str) -> bool:
    """Simple authentication function."""
    return username == 'user' and password == 'pass'


async def main() -> None:
    async with soxy.Proxy(
        protocol=soxy.Socks5(
            auther=auther,
            resolver=soxy.SystemResolver(),  # Required for SOCKS5h and SOCKS4a
        ),
        transport=soxy.TcpTransport(host='127.0.0.1', port=1080),
        ruleset=soxy.Ruleset(
            allow_connecting_rules=[
                soxy.ConnectingRule(
                    from_addresses=IPv4Address('127.0.0.1'),
                )
            ],
            allow_proxying_rules=[
                soxy.ProxyingRule(
                    from_addresses=IPv4Address('127.0.0.1'),
                    to_addresses=IPv4Network('0.0.0.0/0'),
                ),
            ],
        ),
    ) as app:
        await app.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
```

#### Testing with curl

socks5:

```shell
curl -x "socks5://user:pass@127.0.0.1:1080" https://google.com -v
```

socks5h:

```shell
curl -x "socks5h://user:pass@127.0.0.1:1080" https://google.com -v
```

## Configuration

### Configuration File Structure

Configuration is specified in TOML format and consists of three main sections: `[proxy]` (optional), `[transport]` and `[ruleset]` (required).

#### `[proxy]` (optional)

Proxy server settings:

- `protocol` (string): SOCKS protocol (`"socks4"`, `"socks4a"`, `"socks5"`, `"socks5h"`), default `"socks5"`. With `"socks4a"` and `"socks5h"` domain names are resolved on the proxy side
- `transport` (string): Transport protocol (currently only `"tcp"`), default `"tcp"`
- `resolve_timeout` (number, optional): Seconds to wait for resolving a domain name with `"socks4a"` and `"socks5h"` (default `10`)

#### `[proxy.auth]` (optional)

Authentication settings (optional - if omitted, proxy works without authentication):

- For SOCKS5/SOCKS5h: Dictionary mapping `username` to `password`
- For SOCKS4/SOCKS4a: Dictionary with usernames as keys (values are ignored, only presence of username is checked)

Example:
```toml
[proxy.auth]
alice = "password123"
bob = "secret456"
```

#### `[transport]`

Transport layer settings:

- `host` (string): IP address to listen on (e.g., `"127.0.0.1"`, `"0.0.0.0"` or `"::"`)
- `port` (number): Port to listen on (e.g., `1080`)
- `handshake_timeout` (number, optional): Seconds a client has to complete the SOCKS handshake (default `30`)
- `connect_timeout` (number, optional): Seconds to wait for connecting to the destination (default `10`)
- `shutdown_timeout` (number, optional): Seconds to wait for active connections to close on shutdown (default `5`)

#### `[ruleset]`

Access control rules:

- `connecting.allow`: List of rules allowing client connections
- `connecting.block`: List of rules blocking client connections
- `proxying.allow`: List of rules allowing request proxying
- `proxying.block`: List of rules blocking request proxying

Each rule contains:

- `from`: Source IP address or network (IPv4/IPv6 address or CIDR)
- `to`: Destination IP address, network, or domain name (only for proxying rules)

Block rules take precedence over allow rules. Connections that don't match any allow rule are rejected.

### Full Configuration Example

```toml
[proxy]
protocol = "socks5"
transport = "tcp"

# Optional authentication (omit this section for no authentication)
[proxy.auth]
alice = "password123"
bob = "secret456"
charlie = "mypass789"

[transport]
host = "0.0.0.0"
port = 1080

# Connection rules
[[ruleset.connecting.allow]]
from = "127.0.0.1"

[[ruleset.connecting.allow]]
from = "192.168.1.0/24"

[[ruleset.connecting.block]]
from = "10.0.0.1"

# Proxying rules
[[ruleset.proxying.allow]]
from = "127.0.0.1"
to = "0.0.0.0/0"

[[ruleset.proxying.allow]]
from = "192.168.1.0/24"
to = "8.8.8.8"

[[ruleset.proxying.block]]
from = "127.0.0.1"
to = "10.0.0.0/8"
```

## Usage Examples

### Authentication

#### Via Configuration File (CLI)

The simplest way to configure authentication is through the configuration file:

```toml
[proxy]
protocol = "socks5"
transport = "tcp"

# Authentication dictionary: username -> password
[proxy.auth]
alice = "password123"
bob = "secret456"
charlie = "mypass789"

[transport]
host = "127.0.0.1"
port = 1080

[[ruleset.connecting.allow]]
from = "127.0.0.1"

[[ruleset.proxying.allow]]
from = "127.0.0.1"
to = "0.0.0.0/0"
```

For SOCKS4/SOCKS4a (username only, no password):
```toml
[proxy]
protocol = "socks4"

[proxy.auth]
user1 = ""  # Value doesn't matter, only username presence is checked
user2 = ""
admin = ""
```

**Note:** Authentication is optional. If `[proxy.auth]` section is omitted, the proxy works without authentication.

#### Via Code (Programmatic API)

For SOCKS5 and SOCKS4 protocols, you can configure custom authentication programmatically:

```python
async def async_auther(username: str, password: str) -> bool:
    # Asynchronous database check
    # ...
    return True


# Or synchronous function
def sync_auther(username: str, password: str) -> bool:
    return username in allowed_users and check_password(username, password)


protocol = soxy.Socks5(auther=async_auther)  # or sync_auther
```

### Custom Resolver

For working with domain names (SOCKS5h, SOCKS4a), a resolver is required. The built-in `soxy.SystemResolver` uses the system resolver (`getaddrinfo`) with a timeout and supports both IPv4 and IPv6 (IPv4 is preferred when a domain has both):

```python
protocol = soxy.Socks5(
    resolver=soxy.SystemResolver(timeout=5),
)
```

A custom resolver can be a regular or an async function; regular functions are run in a separate thread, so blocking calls don't block the event loop:

```python
async def custom_resolver(domain_name: str) -> IPv4Address | None:
    # Custom resolution logic
    # For example, using DNS-over-HTTPS
    # ...
    return IPv4Address('1.2.3.4')


protocol = soxy.Socks5(
    resolver=custom_resolver,
)
```

### Access Rules

The rule system allows flexible access control:

```python
ruleset = soxy.Ruleset(
    # Allow connections only from local address
    allow_connecting_rules=[
        soxy.ConnectingRule(
            from_addresses=IPv4Address('127.0.0.1'),
        ),
    ],
    # Allow proxying to any addresses
    allow_proxying_rules=[
        soxy.ProxyingRule(
            from_addresses=IPv4Address('127.0.0.1'),
            to_addresses=IPv4Network('0.0.0.0/0'),
        ),
    ],
    # Block proxying to internal networks
    block_proxying_rules=[
        soxy.ProxyingRule(
            from_addresses=IPv4Network('0.0.0.0/0'),
            to_addresses=IPv4Network('10.0.0.0/8'),
        ),
        soxy.ProxyingRule(
            from_addresses=IPv4Network('0.0.0.0/0'),
            to_addresses=IPv4Network('192.168.0.0/16'),
        ),
    ],
)
```

### Using Different Protocols

```python
# SOCKS4
protocol = soxy.Socks4()

# SOCKS4a (with domain name support)
protocol = soxy.Socks4(resolver=soxy.SystemResolver())

# SOCKS5 (without authentication)
protocol = soxy.Socks5()

# SOCKS5 with authentication
protocol = soxy.Socks5(auther=auther)

# SOCKS5h (with domain resolution on proxy side)
protocol = soxy.Socks5(resolver=soxy.SystemResolver())
```

## Development

Development requires [uv](https://docs.astral.sh/uv/) and [just](https://github.com/casey/just).

### Development Installation

```bash
git clone https://github.com/shpaker/soxyproxy.git
cd soxyproxy
uv sync
```

### Running Tests

```bash
# All tests (SOCKS integration tests require internet access)
just tests

# Without SOCKS integration tests
just tests-ci
```

### Code Quality

```bash
# Formatting
just fmt

# Linting
just lint

# Type checking
just mypy
```

## License

This project is licensed under the [GPL-3.0](LICENSE) license.
