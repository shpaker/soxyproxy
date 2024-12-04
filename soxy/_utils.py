import typing

from soxy._errors import PackageError
from soxy._types import Address, IPvAnyAddress, IPvAnyNetwork, SocksVersions


def match_addresses(
    address: Address,
    math_with: IPvAnyAddress | IPvAnyNetwork,
) -> bool:
    result = False
    if isinstance(math_with, typing.get_args(IPvAnyAddress.__value__)):
        result = address.ip == math_with
    if isinstance(math_with, typing.get_args(IPvAnyNetwork.__value__)):
        result = address.ip in math_with
    return result


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
