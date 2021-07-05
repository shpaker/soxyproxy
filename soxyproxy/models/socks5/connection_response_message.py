from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from soxyproxy.consts import Socks5ConnectionReplies, SocksVersion, Socks5AddressTypes
from soxyproxy.models.socks5.common import ResponseMessage
from soxyproxy.consts import (
    SOCKS5_PACKAGE_RESERVED_VALUE,
    SOCKS5_ADDRESS_PORT_BYTES_LENGTH,
    SOCKS5_ADDRESS_PORT_BYTE_ORDER,
)


@dataclass(frozen=True)
class Socks5ConnectionResponseMessage(ResponseMessage):

    reply: Socks5ConnectionReplies
    address: Union[IPv4Address, IPv6Address, str]
    port: int

    @property
    def as_bytes(self):

        response = bytes(
            [
                SocksVersion.SOCKS5.value,
                self.reply.value,
                SOCKS5_PACKAGE_RESERVED_VALUE,
            ]
        )

        if isinstance(self.address, IPv4Address):
            response += bytes([Socks5AddressTypes.IPV4.value]) + self.address.packed

        if isinstance(self.address, IPv6Address):
            response += bytes([Socks5AddressTypes.IPV6.value]) + self.address.packed

        if isinstance(self.address, str):
            address_types = Socks5AddressTypes.DOMAIN
            response += (
                bytes([address_types.value, len(self.address)]) + self.address.encode()
            )

        return response + int.to_bytes(
            self.port, SOCKS5_ADDRESS_PORT_BYTES_LENGTH, SOCKS5_ADDRESS_PORT_BYTE_ORDER
        )
