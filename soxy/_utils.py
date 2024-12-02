from soxy._errors import (
    PackageError,
)
from soxy._types import (
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
