from ipaddress import IPv4Address
from typing import Any, Dict

from pydantic import validator

from soxyproxy.consts import (
    SOCKS4_ADDRESS_PORT_BYTES_ORDER,
    SOCKS4_ADDRESS_PORT_BYTES_LENGTH,
    SocksVersion,
    Socks4Command,
)
from soxyproxy.models.base import RequestBaseModel

SOCKS_VERSION_INDEX = 0
COMMAND_INDEX = 1
DESTINATION_PORT_SLICE = slice(2, 2 + SOCKS4_ADDRESS_PORT_BYTES_LENGTH)
DESTINATION_ADDRESS_SLICE = slice(4, 8)
USER_ID_SLICE = slice(8, -1)
NULL_TERMINATING_CHAR_INDEX = -1


def extract_protocol(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_command(raw: bytes) -> int:
    return raw[COMMAND_INDEX]


def extract_port(raw: bytes) -> int:
    raw_port = raw[DESTINATION_PORT_SLICE]
    return int.from_bytes(raw_port, byteorder=SOCKS4_ADDRESS_PORT_BYTES_ORDER)


def extract_address(raw: bytes) -> bytes:
    return raw[DESTINATION_ADDRESS_SLICE]


def check_raw_length(raw: bytes) -> None:
    data_len = len(raw)
    if data_len < 9:
        raise ValueError(f"incorrect package size: {raw} ({data_len} bytes)")


def check_null_terminating_char(raw: bytes) -> None:
    if raw[NULL_TERMINATING_CHAR_INDEX] != 0x0:
        raise ValueError(f"package should be null-terminated: {raw}")


def message_loads(raw: bytes) -> Dict[str, Any]:
    check_raw_length(raw)
    check_null_terminating_char(raw)
    socks_version = extract_protocol(raw)
    return dict(
        protocol=socks_version,
        command=extract_command(raw),
        address=extract_address(raw),
        port=extract_port(raw),
    )


class RequestModel(RequestBaseModel):
    protocol: SocksVersion
    command: Socks4Command
    port: int
    address: IPv4Address

    @validator("protocol")
    def protocol_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ):
        if value != 4:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @classmethod
    def loads(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        data = message_loads(raw)
        return cls(**data)
