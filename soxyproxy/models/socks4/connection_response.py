from ipaddress import IPv4Address

from soxyproxy.consts import (
    Socks4Reply,
    SOCKS4_ADDRESS_PORT_BYTES_LENGTH,
    SOCKS4_ADDRESS_PORT_BYTES_ORDER,
)
from soxyproxy.models.base import ResponseBaseModel


class ResponseModel(ResponseBaseModel):
    reply_version: int = 0
    reply: Socks4Reply
    port: int
    address: IPv4Address

    def dumps(self):
        port_bytes = int.to_bytes(
            self.port,
            SOCKS4_ADDRESS_PORT_BYTES_LENGTH,
            SOCKS4_ADDRESS_PORT_BYTES_ORDER,
        )
        return (
            bytes([self.reply_version, self.reply.value])
            + port_bytes
            + self.address.packed
        )
