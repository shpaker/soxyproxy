from dataclasses import dataclass
from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
from logging import getLogger
from socket import gethostbyname
from typing import Union

from soxyproxy.consts import (
    SOCKS5_ADDRESS_PORT_BYTES_LENGTH,
    SOCKS5_ADDRESS_OCTET_LENGTH,
    SOCKS5_PACKAGE_RESERVED_VALUE,
    SOCKS5_ADDRESS_PORT_BYTE_ORDER,
)
from soxyproxy.consts import Socks5Commands, SocksVersion, Socks5AddressTypes
from soxyproxy.models.socks5.common import RequestMessage

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


@dataclass(frozen=True)
class Socks5ConnectionRequestMessage(RequestMessage):

    action: Socks5Commands
    address: Union[IPv4Address, IPv6Address]
    port: int

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = SocksVersion(raw[SOCKS_VERSION_INDEX])
        except (ValueError, IndexError) as err:
            raise ValueError(f"incorrect connection package: {raw}") from err

        if socks_version != SocksVersion.SOCKS5:
            raise ValueError(f"incorrect connection package: {raw}")

        connection_type = Socks5Commands(raw[CONNECTION_COMMAND_INDEX])
        reserved_value = raw[RESERVED_VALUE_INDEX]

        if reserved_value != SOCKS5_PACKAGE_RESERVED_VALUE:
            raise ValueError(f"incorrect connection package: {raw}")

        destination_port = Socks5ConnectionRequestMessage.get_port_from_raw(raw)

        # try:
        destination_address = Socks5ConnectionRequestMessage.get_address_from_raw(raw)
        # except gaierror:
        #     raise

        return Socks5ConnectionRequestMessage(
            action=connection_type, address=destination_address, port=destination_port
        )

    @staticmethod
    def get_address_from_raw(raw: bytes) -> Union[IPv4Address, IPv6Address]:

        address_type = Socks5AddressTypes(raw[ADDRESS_TYPE_INDEX])

        if address_type == Socks5AddressTypes.IPV6:
            raw_address = raw[IPV6_DESTINATION_ADDRESS_SLICE]
            return IPv6Address(raw_address)

        if address_type == Socks5AddressTypes.DOMAIN:
            domain_name = Socks5ConnectionRequestMessage.get_domain_name_from_raw(raw)
            ipv4 = gethostbyname(domain_name)

            logger.info(f"Hostname {domain_name} successfully resolved to {ipv4}")
            return ipv4
        # if address_type == AddressTypes.IPv4:
        ipv4 = raw[IPV4_DESTINATION_ADDRESS_SLICE]

        addr = IPv4Address(ipv4)
        return addr

    @staticmethod
    def get_domain_name_from_raw(raw: bytes) -> str:
        domain_slice = slice(
            DOMAIN_NAME_INDEX, DOMAIN_NAME_INDEX + raw[DOMAIN_LEN_INDEX]
        )
        return raw[domain_slice].decode()

    @staticmethod
    def get_port_from_raw(raw: bytes) -> int:
        return int.from_bytes(
            bytes=raw[DESTINATION_PORT_SLICE],
            byteorder=SOCKS5_ADDRESS_PORT_BYTE_ORDER,
        )
