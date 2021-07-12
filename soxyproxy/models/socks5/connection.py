from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
from logging import getLogger
from socket import gethostbyname
from typing import Optional, Tuple, Union

from pydantic import validator

from soxyproxy.consts import (
    PORT_BYTES_LENGTH,
    PORT_BYTES_ORDER,
    Socks5AddressType,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersion,
)
from soxyproxy.models.base import RequestBaseModel, ResponseBaseModel

SOCKS5_PACKAGE_RESERVED_VALUE = 0
SOCKS5_ADDRESS_OCTET_LENGTH = 8
SOCKS_VERSION_INDEX = 0
CONNECTION_COMMAND_INDEX = 1
RESERVED_VALUE_INDEX = 2
ADDRESS_TYPE_INDEX = 3
IPV4_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV4LENGTH // SOCKS5_ADDRESS_OCTET_LENGTH)
IPV6_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV6LENGTH // SOCKS5_ADDRESS_OCTET_LENGTH)
DOMAIN_LEN_INDEX = 4
DOMAIN_NAME_INDEX = 5
DESTINATION_PORT_SLICE = slice(-PORT_BYTES_LENGTH, None)

logger = getLogger()


def extract_socks_version(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_action(raw: bytes) -> int:
    return raw[CONNECTION_COMMAND_INDEX]


def extract_reserved_value(raw: bytes) -> int:
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
        byteorder=PORT_BYTES_ORDER,
    )


def extract_address(
    raw: bytes,
) -> Tuple[Union[IPv4Address, IPv6Address], Optional[str]]:
    address_type = Socks5AddressType(raw[ADDRESS_TYPE_INDEX])

    if address_type == Socks5AddressType.IPV6:
        raw_address = raw[IPV6_DESTINATION_ADDRESS_SLICE]
        return IPv6Address(raw_address), None

    if address_type == Socks5AddressType.DOMAIN:
        domain_name = extract_domain_name(raw)
        address = gethostbyname(domain_name)
        return IPv4Address(address), domain_name

    ipv4 = raw[IPV4_DESTINATION_ADDRESS_SLICE]
    return IPv4Address(ipv4), None


class RequestModel(RequestBaseModel["RequestModel"]):
    socks_version: SocksVersion
    action: Socks5Command
    address: Union[IPv4Address, IPv6Address]
    domain: Optional[str] = None
    port: int
    reserved_value: int = 0

    @validator("socks_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ) -> int:
        if value != SocksVersion.SOCKS5:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @validator("reserved_value")
    def reserved_value_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ) -> int:
        if value != SOCKS5_PACKAGE_RESERVED_VALUE:
            raise ValueError(f"incorrect reserved value: {value}")
        return value

    @classmethod
    def loader(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        address, domain = extract_address(raw)
        return cls(
            socks_version=extract_socks_version(raw),
            action=extract_action(raw),
            address=address,
            domain=domain,
            port=extract_port(raw),
            reserved_value=extract_reserved_value(raw),
        )


class ResponseModel(ResponseBaseModel):
    reply: Socks5ConnectionReply
    address: Union[IPv4Address, IPv6Address, str]
    port: int

    def dump(self) -> bytes:
        response = bytes(
            [
                SocksVersion.SOCKS5.value,
                self.reply.value,
                SOCKS5_PACKAGE_RESERVED_VALUE,
            ]
        )
        if isinstance(self.address, IPv4Address):
            response += bytes([Socks5AddressType.IPV4.value]) + self.address.packed
        if isinstance(self.address, IPv6Address):
            response += bytes([Socks5AddressType.IPV6.value]) + self.address.packed
        if isinstance(self.address, str):
            address_types = Socks5AddressType.DOMAIN
            response += bytes([address_types.value, len(self.address)]) + self.address.encode()
        return response + int.to_bytes(self.port, PORT_BYTES_LENGTH, PORT_BYTES_ORDER)
