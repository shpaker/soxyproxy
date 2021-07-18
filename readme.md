# SoxyProxy

[![PyPI version](https://badge.fury.io/py/soxyproxy.svg)](https://badge.fury.io/py/soxyproxy)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/shpaker/soxyproxy.svg?logo=lgtm)](https://lgtm.com/projects/g/shpaker/soxyproxy/context:python)
[![Test](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

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

## Configuration

### Apache-Like Authentication (htpasswd)

https://pypi.org/project/pypiserver/#apache-like-authentication-htpasswd

### Rulesets
