from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from soxyproxy.socks import ProtocolResponse
from soxyproxy.socks4.messages import PORT_BYTES_LENGTH
from soxyproxy.socks5.codes import ReplyCodes, RESERVED_VALUE, AddressTypes, ADDRESS_PORT_BYTE_ORDER
from soxyproxy.socks_versions import SocksVersions


@dataclass(frozen=True)
class ConnectionResponse(ProtocolResponse):

    reply_code: ReplyCodes
    address: Union[IPv4Address, IPv6Address, str]
    port: int

    @property
    def as_bytes(self):

        response = bytes([SocksVersions.SOCKS5.value, self.reply_code.value, RESERVED_VALUE])

        if isinstance(self.address, IPv4Address):
            response += bytes([AddressTypes.IPv4.value]) + self.address.packed

        if isinstance(self.address, IPv6Address):
            response += bytes([AddressTypes.IPv6.value]) + self.address.packed

        if isinstance(self.address, str):
            address_types = AddressTypes.DOMAIN
            response += bytes([address_types.value, len(self.address)]) + self.address.encode()

        return response + int.to_bytes(self.port, PORT_BYTES_LENGTH, ADDRESS_PORT_BYTE_ORDER)
