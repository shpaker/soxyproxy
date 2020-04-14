from dataclasses import dataclass
from ipaddress import IPv4Address

from soxyproxy.socks import ResponseMessage
from soxyproxy.socks4 import Socks4Replies
from soxyproxy.socks4.messages.const import SOCKS4_ADDRESS_PORT_BYTES_LENGTH, SOCKS4_ADDRESS_PORT_BYTES_ORDER

SOCKS4_REPLY_VERSION = 0


@dataclass
class Socks4ConnectionResponseMessage(ResponseMessage):

    reply: Socks4Replies
    port: int
    address: IPv4Address

    @property
    def as_bytes(self):
        port_bytes = int.to_bytes(self.port, SOCKS4_ADDRESS_PORT_BYTES_LENGTH, SOCKS4_ADDRESS_PORT_BYTES_ORDER)

        return bytes([SOCKS4_REPLY_VERSION, self.reply.value]) + port_bytes + self.address.packed
