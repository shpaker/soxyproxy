from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
from logging import getLogger
from socket import gethostbyname
from typing import Union

from pydantic import validator

from soxyproxy.consts import (
    SOCKS5_ADDRESS_PORT_BYTES_LENGTH,
    SOCKS5_ADDRESS_OCTET_LENGTH,
    SOCKS5_PACKAGE_RESERVED_VALUE,
    SOCKS5_ADDRESS_PORT_BYTE_ORDER,
)
from soxyproxy.consts import Socks5Commands, SocksVersion, Socks5AddressTypes
from soxyproxy.models.base import RequestBaseModel

SOCKS_VERSION_INDEX = 0
CONNECTION_COMMAND_INDEX = 1
RESERVED_VALUE_INDEX = 2
ADDRESS_TYPE_INDEX = 3
IPV4_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV4LENGTH // SOCKS5_ADDRESS_OCTET_LENGTH)
IPV6_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV6LENGTH // SOCKS5_ADDRESS_OCTET_LENGTH)
DOMAIN_LEN_INDEX = 4
DOMAIN_NAME_INDEX = 5
DESTINATION_PORT_SLICE = slice(-SOCKS5_ADDRESS_PORT_BYTES_LENGTH, None)

logger = getLogger()


def extract_socks_version(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_action(raw):
    return raw[CONNECTION_COMMAND_INDEX]


def extract_reserved_value(raw):
    return raw[RESERVED_VALUE_INDEX]


def extract_domain_name(raw: bytes) -> str:
    domain_slice = slice(
        DOMAIN_NAME_INDEX,
        DOMAIN_NAME_INDEX + raw[DOMAIN_LEN_INDEX],
    )
    return raw[domain_slice].decode()


def extract_port(raw: bytes) -> int:
    return int.from_bytes(
        bytes=raw[DESTINATION_PORT_SLICE],
        byteorder=SOCKS5_ADDRESS_PORT_BYTE_ORDER,
    )


def extract_address(raw: bytes) -> Union[IPv4Address, IPv6Address]:
    address_type = Socks5AddressTypes(raw[ADDRESS_TYPE_INDEX])

    if address_type == Socks5AddressTypes.IPV6:
        raw_address = raw[IPV6_DESTINATION_ADDRESS_SLICE]
        return IPv6Address(raw_address)

    if address_type == Socks5AddressTypes.DOMAIN:
        domain_name = extract_domain_name(raw)
        address = gethostbyname(domain_name)
        return IPv4Address(address)

    ipv4 = raw[IPV4_DESTINATION_ADDRESS_SLICE]
    return IPv4Address(ipv4)


class RequestModel(RequestBaseModel):
    socks_version: SocksVersion
    action: Socks5Commands
    address: Union[IPv4Address, IPv6Address]
    port: int
    reserved_value: int = 0

    @validator("socks_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ):
        if value != SocksVersion.SOCKS5:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @validator("reserved_value")
    def reserved_value_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ):
        if value != SOCKS5_PACKAGE_RESERVED_VALUE:
            raise ValueError(f"incorrect reserved value: {value}")
        return value

    @classmethod
    def loads(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        return cls(
            socks_version=extract_socks_version(raw),
            action=extract_action(raw),
            address=extract_address(raw),
            port=extract_port(raw),
            reserved_value=extract_reserved_value(raw),
        )
