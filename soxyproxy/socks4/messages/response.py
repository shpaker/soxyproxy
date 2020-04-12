from dataclasses import dataclass
from ipaddress import IPv4Address

from noSocks.socks4.codes import ReplyCodes
from noSocks.socks4 import PORT_BYTES_ORDER, PORT_BYTES_LENGTH


@dataclass
class Response:

    reply_code: ReplyCodes
    destination_port: int
    destination_address: IPv4Address

    reply_version: int = 0

    @property
    def as_bytes(self):

        port_bytes = int.to_bytes(self.destination_port, PORT_BYTES_LENGTH, PORT_BYTES_ORDER)

        return bytes([self.reply_version, self.reply_code.value]) + port_bytes + self.destination_address.packed
