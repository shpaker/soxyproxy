from dataclasses import dataclass
from ipaddress import IPv4Address

from soxyproxy.consts import ProtocolsEnum
from soxyproxy.server import RequestMessage
from soxyproxy.socks4.codes import Socks4Commands
from soxyproxy.socks4.messages.const import (
    SOCKS4_ADDRESS_PORT_BYTES_LENGTH,
    SOCKS4_ADDRESS_PORT_BYTES_ORDER,
)

SOCKS_VERSION_INDEX = 0
COMMAND_INDEX = 1
DESTINATION_PORT_SLICE = slice(2, 2 + SOCKS4_ADDRESS_PORT_BYTES_LENGTH)
DESTINATION_ADDRESS_SLICE = slice(4, 8)
USER_ID_SLICE = slice(8, -1)
NULL_TERMINATING_CHAR = 0
NULL_TERMINATING_CHAR_INDEX = -1


@dataclass(frozen=True)
class Socks4ConnectionRequestMessage(RequestMessage):

    command: Socks4Commands
    port: int
    address: IPv4Address

    @staticmethod
    def from_bytes(raw: bytes):
        try:
            socks_version = ProtocolsEnum(raw[SOCKS_VERSION_INDEX])
            if socks_version is not ProtocolsEnum.SOCKS4:
                raise ValueError
        except (ValueError, IndexError) as err:
            raise ValueError(f"incorrect handshake package: {raw}") from err

        try:
            command = Socks4Commands(raw[COMMAND_INDEX])
        except KeyError as err:
            raise ValueError(f"incorrect handshake package: {raw}") from err

        address = IPv4Address(raw[DESTINATION_ADDRESS_SLICE])
        port = int.from_bytes(
            raw[DESTINATION_PORT_SLICE], byteorder=SOCKS4_ADDRESS_PORT_BYTES_ORDER
        )

        if raw[NULL_TERMINATING_CHAR_INDEX] != NULL_TERMINATING_CHAR:
            raise ValueError(f"incorrect handshake package: {raw}")

        return Socks4ConnectionRequestMessage(
            command=command, address=address, port=port
        )

    @staticmethod
    def get_address_from_raw(raw):
        return IPv4Address(raw[DESTINATION_ADDRESS_SLICE])

    @staticmethod
    def get_port_from_raw(raw):
        return int.from_bytes(
            raw[DESTINATION_PORT_SLICE], byteorder=SOCKS4_ADDRESS_PORT_BYTES_ORDER
        )
