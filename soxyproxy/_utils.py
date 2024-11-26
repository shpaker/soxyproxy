from ipaddress import IPv4Address
from socket import gethostbyname

from soxyproxy._errors import SocksIncorrectVersionError, SocksPackageError
from soxyproxy._logger import logger
from soxyproxy._types import SocksVersions


def port_from_bytes(
    data: bytes,
) -> int:
    return int.from_bytes(data, byteorder='big')


def port_to_bytes(
    data: int,
) -> bytes:
    return int.to_bytes(data, 2, byteorder='big')


def resolve_host(
    domain: str | int,
) -> IPv4Address:
    logger.info(f'Host {domain} was resolved')
    return IPv4Address(gethostbyname(domain))


def check_protocol_version(
    data: bytes,
    socks_version: SocksVersions,
) -> None:
    if not data:
        raise SocksPackageError(data)
    if data[0] != socks_version:
        raise SocksIncorrectVersionError(data)
