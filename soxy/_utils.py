from asyncio import iscoroutine
from ipaddress import IPv4Address
from traceback import print_exc
from typing import get_args

from soxy._errors import (
    AuthorizationError,
    PackageError,
    ResolveDomainError,
)
from soxy._logger import logger
from soxy._types import (
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
        byteorder="big",
    )


def port_to_bytes(
    data: int,
) -> bytes:
    return int.to_bytes(
        data,
        2,
        byteorder="big",
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
    domain_name: str,
) -> IPv4Address:
    try:
        result = resolver(domain_name)
        if iscoroutine(result):
            result = await result
    except Exception as exc:
        raise ResolveDomainError(domain_name=domain_name) from exc
    message = (
        f"fail to resolve {domain_name}"
        if not result
        else f"host {domain_name} was resolved: IPv4 {result}"
    )
    logger.info(message)
    if not result:
        raise ResolveDomainError(domain_name=domain_name, port=0)
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
        return destination.ip == math_with
    return destination.ip in math_with
