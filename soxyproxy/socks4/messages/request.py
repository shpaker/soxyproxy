from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Optional

from noSocks.socks.exceptions import SocksIncorrectRequest
from noSocks.socks import SocksVersions
from noSocks.socks4.codes import ConnectionTypes
from noSocks.socks4 import PORT_BYTES_ORDER

SOCKS_VERSION_INDEX = 0
COMMAND_INDEX = 1
DESTINATION_PORT_SLICE = slice(2, 4)
DESTINATION_ADDRESS_SLICE = slice(4, 8)
USER_ID_SLICE = slice(8, -1)
NULL_TERMINATING_CHAR = 0
NULL_TERMINATING_CHAR_INDEX = -1


@dataclass(frozen=True)
class Request:

    command: ConnectionTypes
    remote_port: int
    remote_address: IPv4Address

    socks_version: SocksVersions = SocksVersions.SOCKS4
    user_id: Optional[str] = None


def request_from_bytes(raw: bytes) -> Request:

    if SocksVersions(raw[SOCKS_VERSION_INDEX]) != SocksVersions.SOCKS4:
        raise SocksIncorrectRequest

    try:
        command = ConnectionTypes(raw[COMMAND_INDEX])
    except KeyError:
        raise SocksIncorrectRequest

    destination_address = IPv4Address(raw[DESTINATION_ADDRESS_SLICE])
    destination_port = int.from_bytes(raw[DESTINATION_PORT_SLICE], byteorder=PORT_BYTES_ORDER)
    user_id: Optional[str] = raw[USER_ID_SLICE].decode() if raw[USER_ID_SLICE] else None

    if raw[NULL_TERMINATING_CHAR_INDEX] != NULL_TERMINATING_CHAR:
        raise SocksIncorrectRequest

    return Request(command=command,
                   destination_address=destination_address,
                   destination_port=destination_port,
                   user_id=user_id)
