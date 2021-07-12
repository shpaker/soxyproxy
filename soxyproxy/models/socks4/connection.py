from ipaddress import IPv4Address

from pydantic import validator

from soxyproxy.consts import PORT_BYTES_LENGTH, PORT_BYTES_ORDER, Socks4Command, Socks4Reply, SocksVersion
from soxyproxy.models.base import RequestBaseModel, ResponseBaseModel

SOCKS_VERSION_INDEX = 0
COMMAND_INDEX = 1
DESTINATION_PORT_SLICE = slice(2, 2 + PORT_BYTES_LENGTH)
DESTINATION_ADDRESS_SLICE = slice(4, 8)
USER_ID_SLICE = slice(8, -1)
NULL_TERMINATING_CHAR_INDEX = -1


def extract_socks_version(raw: bytes) -> int:
    return raw[SOCKS_VERSION_INDEX]


def extract_command(raw: bytes) -> int:
    return raw[COMMAND_INDEX]


def extract_port(raw: bytes) -> int:
    raw_port = raw[DESTINATION_PORT_SLICE]
    return int.from_bytes(raw_port, byteorder=PORT_BYTES_ORDER)


def extract_address(raw: bytes) -> bytes:
    return raw[DESTINATION_ADDRESS_SLICE]


def check_raw_length(raw: bytes) -> None:
    data_len = len(raw)
    if data_len < 9:
        raise ValueError(f"incorrect package size: {str(raw)} ({data_len} bytes)")


def check_null_terminating_char(raw: bytes) -> None:
    if raw[NULL_TERMINATING_CHAR_INDEX] != 0x0:
        raise ValueError(f"package should be null-terminated: {str(raw)}")


class RequestModel(RequestBaseModel["RequestModel"]):
    socks_version: SocksVersion
    command: Socks4Command
    port: int
    address: IPv4Address

    @validator("socks_version")
    def socks_version_validator(  # pylint: disable=no-self-argument, no-self-use
        cls,
        value: int,
    ) -> int:
        if value != SocksVersion.SOCKS4:
            raise ValueError(f"incorrect protocol version: {value}")
        return value

    @classmethod
    def loader(
        cls,
        raw: bytes,
    ) -> "RequestModel":
        check_raw_length(raw)
        check_null_terminating_char(raw)
        return cls(
            socks_version=extract_socks_version(raw),
            command=extract_command(raw),
            address=extract_address(raw),
            port=extract_port(raw),
        )


class ResponseModel(ResponseBaseModel):
    reply_version: int = 0
    reply: Socks4Reply
    port: int
    address: IPv4Address

    def dump(self) -> bytes:
        port_bytes = int.to_bytes(
            self.port,
            PORT_BYTES_LENGTH,
            PORT_BYTES_ORDER,
        )
        return bytes([self.reply_version, self.reply.value]) + port_bytes + self.address.packed
