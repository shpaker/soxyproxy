from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, IPV4LENGTH, IPV6LENGTH
from logging import getLogger
from socket import gethostbyname, gaierror
from typing import Union

from soxyproxy.socks import ProtocolRequest
from soxyproxy.socks5.codes import (RESERVED_VALUE, AddressTypes, ADDRESS_OCTET_LENGTH, ADDRESS_PORT_BYTE_ORDER,
                                    ConnectionTypes)
from soxyproxy.socks_versions import SocksVersions

SOCKS_VERSION_INDEX = 0
CONNECTION_TYPES_INDEX = 1
RESERVED_VALUE_INDEX = 2
ADDRESS_TYPE_INDEX = 3
IPV4_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV4LENGTH // ADDRESS_OCTET_LENGTH)
IPV6_DESTINATION_ADDRESS_SLICE = slice(4, 4 + IPV6LENGTH // ADDRESS_OCTET_LENGTH)
DOMAIN_LEN_INDEX = 4
DOMAIN_NAME_INDEX = 5
DESTINATION_PORT_SLICE = slice(-2, None)

logger = getLogger()


@dataclass(frozen=True)
class ConnectionRequest(ProtocolRequest):

    action: ConnectionTypes
    address: Union[IPv4Address, IPv6Address]
    port: int

    @staticmethod
    def from_bytes(raw: bytes):

        try:
            socks_version = SocksVersions(raw[SOCKS_VERSION_INDEX])
        except (ValueError, IndexError):
            raise ValueError(f'incorrect connection package: {raw}')

        if socks_version != SocksVersions.SOCKS5:
            raise ValueError(f'incorrect connection package: {raw}')

        connection_type = ConnectionTypes(raw[CONNECTION_TYPES_INDEX])
        reserved_value = raw[RESERVED_VALUE_INDEX]

        if reserved_value != RESERVED_VALUE:
            raise ValueError(f'incorrect connection package: {raw}')

        destination_port = ConnectionRequest.get_port_from_raw(raw)

        try:
            destination_address = ConnectionRequest.get_address_from_raw(raw)
        except gaierror:
            raise

        return ConnectionRequest(action=connection_type, address=destination_address, port=destination_port)

    @staticmethod
    def get_address_from_raw(raw: bytes) -> Union[IPv4Address, IPv6Address]:

        address_type = AddressTypes(raw[ADDRESS_TYPE_INDEX])

        if address_type == AddressTypes.IPv6:
            raw_address = raw[IPV6_DESTINATION_ADDRESS_SLICE]
            return IPv6Address(raw_address)

        if address_type == AddressTypes.DOMAIN:
            domain_name = ConnectionRequest.get_domain_name_from_raw(raw)
            ipv4 = gethostbyname(domain_name)

            logger.info(f'Hostname {domain_name} successfully resolved to {ipv4}')

        # if address_type == AddressTypes.IPv4:
        ipv4 = raw[IPV4_DESTINATION_ADDRESS_SLICE]

        return IPv4Address(ipv4)

    @staticmethod
    def get_domain_name_from_raw(raw: bytes) -> str:
        domain_slice = slice(DOMAIN_NAME_INDEX, DOMAIN_NAME_INDEX + raw[DOMAIN_LEN_INDEX])
        return raw[domain_slice].decode()

    @staticmethod
    def get_port_from_raw(raw: bytes) -> int:
        return int.from_bytes(bytes=raw[DESTINATION_PORT_SLICE], byteorder=ADDRESS_PORT_BYTE_ORDER)
