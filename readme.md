# SoxyProxy

## Getting Started

### Installing

SoxyProxy can be installed using pip:

```bash
pip install soxyproxy
```

## Usage

To test that installation was successful, try:

```bash
python -m soxyproxy --help
```

## Features

### Protocols

- [x] SOCKS4

- [x] SOCKS5

  * Protocols
    * [x] TCP
    * [ ] UDP

  * Auth
    * [x] None
    * [x] Login/Password
    * [ ] GSSAPI

  * CMC
    * [x] Connect
    * [ ] Bind
    * [ ] ASSOCIATE

  * ADDR
    * [x] IPv4
    * [x] IPv6
    * [x] Domain

### Rulesets
