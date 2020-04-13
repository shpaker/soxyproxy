from dataclasses import dataclass
from ipaddress import IPv4Address

from soxyproxy.socks import ProtocolResponse
from soxyproxy.socks4.codes import ReplyCodes, ADDRESS_PORT_BYTES_LENGTH, ADDRESS_PORT_BYTES_ORDER


@dataclass
class ConnectionResponse(ProtocolResponse):

    reply: ReplyCodes
    port: int
    address: IPv4Address

    reply_version: int = 0

    @property
    def as_bytes(self):

        port_bytes = int.to_bytes(self.port, ADDRESS_PORT_BYTES_LENGTH, ADDRESS_PORT_BYTES_ORDER)

        return bytes([self.reply_version, self.reply.value]) + port_bytes + self.address.packed
