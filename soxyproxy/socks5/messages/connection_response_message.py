from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from soxyproxy.protocols import Protocols
from soxyproxy.socks import ResponseMessage
from soxyproxy.socks5 import Socks5ConnectionReplies, Socks5AddressTypes
from soxyproxy.socks5.messages.const import (SOCKS5_PACKAGE_RESERVED_VALUE, SOCKS5_ADDRESS_PORT_BYTES_LENGTH,
                                             SOCKS5_ADDRESS_PORT_BYTE_ORDER)


@dataclass(frozen=True)
class Socks5ConnectionResponseMessage(ResponseMessage):

    reply: Socks5ConnectionReplies
    address: Union[IPv4Address, IPv6Address, str]
    port: int

    @property
    def as_bytes(self):

        response = bytes([Protocols.SOCKS5.value, self.reply.value, SOCKS5_PACKAGE_RESERVED_VALUE])

        if isinstance(self.address, IPv4Address):
            response += bytes([Socks5AddressTypes.IPv4.value]) + self.address.packed

        if isinstance(self.address, IPv6Address):
            response += bytes([Socks5AddressTypes.IPv6.value]) + self.address.packed

        if isinstance(self.address, str):
            address_types = Socks5AddressTypes.DOMAIN
            response += bytes([address_types.value, len(self.address)]) + self.address.encode()

        return response + int.to_bytes(self.port, SOCKS5_ADDRESS_PORT_BYTES_LENGTH, SOCKS5_ADDRESS_PORT_BYTE_ORDER)
