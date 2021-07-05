from enum import unique, IntEnum

SOCKS4_ADDRESS_PORT_BYTES_LENGTH = 2
SOCKS4_ADDRESS_PORT_BYTES_ORDER = "big"


@unique
class SocksVersion(IntEnum):
    SOCKS4 = 4
    SOCKS5 = 5


@unique
class Socks4Command(IntEnum):
    CONNECT = 1
    BIND = 2


@unique
class Socks4Reply(IntEnum):
    GRANTED = 0x5A  # Request granted
    REJECTED = 0x5B  # Request rejected or failed
    # Failed because client is not running identd (or not reachable from server)
    IDENTD_NOT_REACHABLE = 0x5C
    # Failed because client's identd could not confirm the user ID in the request
    IDENTD_REJECTED = 0x5D
