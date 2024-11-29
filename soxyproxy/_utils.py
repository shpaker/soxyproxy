from asyncio import iscoroutine
from ipaddress import IPv4Address

from soxyproxy._errors import (
    AuthorizationError,
    PackageError,
    ResolveDomainError,
)
from soxyproxy._logger import logger
from soxyproxy._types import (
    Resolver,
    Socks4Auther,
    Socks5Auther,
    SocksVersions,
)


def port_from_bytes(
    data: bytes,
) -> int:
    return int.from_bytes(data, byteorder="big")


def port_to_bytes(
    data: int,
) -> bytes:
    return int.to_bytes(data, 2, byteorder="big")


def check_protocol_version(
    data: bytes,
    socks_version: SocksVersions,
) -> None:
    if not data:
        raise PackageError(data)
    if data[0] != socks_version:
        raise PackageError(data)


async def call_domain_names_resolver(
    resolver: Resolver,
    name: str,
) -> IPv4Address:
    try:
        result = resolver(name)
        if iscoroutine(result):
            result = await result
    except Exception:  # noqa: BLE001
        result = False
    message = (
        f"fail to resolve {name}"
        if not result
        else f"host {name} was resolved: IPv4 {result}"
    )
    logger.info(message)
    if not result:
        raise ResolveDomainError(name)
    return result


async def call_user_auther(
    auther: Socks4Auther,
    username: str,
) -> bool:
    try:
        result = auther(username)
        if iscoroutine(result):
            result = await result
    except Exception:  # noqa: BLE001
        result = False
    message = (
        f"fail to authorize {username}" if not result else f"{username} authorized"
    )
    logger.info(message)
    if not result:
        raise AuthorizationError(username)
    return result


async def call_user_pass_auther(
    auther: Socks5Auther,
    username: str,
    password: str,
) -> bool:
    try:
        result = auther(username, password)
        if iscoroutine(result):
            result = await result
    except Exception:  # noqa: BLE001
        result = False
    message = (
        f"fail to authorize {username}" if not result else f"{username} authorized"
    )
    logger.info(message)
    if not result:
        raise AuthorizationError(username)
    return result
