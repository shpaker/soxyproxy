from asyncio import iscoroutine
from ipaddress import IPv4Address
from traceback import print_exc
from typing import get_args

from soxyproxy._errors import (
    AuthorizationError,
    PackageError,
    ResolveDomainError,
)
from soxyproxy._logger import logger
from soxyproxy._types import (
    Address,
    IPvAnyAddress,
    Resolver,
    Socks4Auther,
    Socks5Auther,
    SocksVersions,
)


def port_from_bytes(
    data: bytes,
) -> int:
    return int.from_bytes(
        data,
        byteorder='big',
    )


def port_to_bytes(
    data: int,
) -> bytes:
    return int.to_bytes(
        data,
        2,
        byteorder='big',
    )


def check_protocol_version(
    data: bytes,
    socks_version: SocksVersions,
) -> None:
    if not data:
        raise PackageError(data)
    if data[0] != socks_version:
        raise PackageError(data)


async def call_resolver(
    resolver: Resolver,
    name: str,
) -> IPv4Address:
    try:
        result = resolver(name)
        if iscoroutine(result):
            result = await result
    except Exception as exc:
        raise ResolveDomainError(name) from exc
    message = (
        f'fail to resolve {name}'
        if not result
        else f'host {name} was resolved: IPv4 {result}'
    )
    logger.info(message)
    if not result:
        raise ResolveDomainError(name)
    return result


async def call_user_auther(
    auther: Socks4Auther,
    username: str,
) -> None:
    try:
        result = auther(username)
        if iscoroutine(result):
            result = await result
    except Exception:  # noqa: BLE001
        print_exc()
        result = False
    if not result:
        raise AuthorizationError(username)


async def call_user_pass_auther(
    auther: Socks5Auther,
    username: str,
    password: str,
) -> None:
    try:
        result = auther(username, password)
        if iscoroutine(result):
            result = await result
    except Exception:  # noqa: BLE001  # noqa: BLE001
        print_exc()
        result = False
    if not result:
        raise AuthorizationError(username)


def match_addresses(
    destination: Address,
    math_with: IPvAnyAddress | IPvAnyAddress,
) -> bool:
    if isinstance(math_with, get_args(IPvAnyAddress.__value__)):
        return destination.address == math_with
    return destination.address in math_with
