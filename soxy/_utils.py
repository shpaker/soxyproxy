from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TYPE_CHECKING

from soxy._errors import PackageError

if TYPE_CHECKING:
    from soxy._types import Address, IPvAnyAddress, IPvAnyNetwork, SocksVersions


def match_addresses(
    address: Address,
    match_with: IPvAnyAddress | IPvAnyNetwork,
) -> bool:
    if isinstance(match_with, IPv4Address | IPv6Address):
        return address.ip == match_with
    if isinstance(match_with, IPv4Network | IPv6Network):
        return address.ip in match_with
    return False


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
