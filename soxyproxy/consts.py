from enum import Enum, IntEnum, unique

PORT_BYTES_LENGTH = 2
PORT_BYTES_ORDER = "big"


class Auther(str, Enum):
    PAM = "pam"
    HTPASSWD = "htpasswd"


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


@unique
class Socks5AuthMethod(IntEnum):
    NO_AUTHENTICATION = 0
    GSSAPI = 1
    USERNAME = 2
    NO_ACCEPTABLE = 255


@unique
class Socks5AuthReply(IntEnum):
    SUCCESS = 0
    FAIL = 1


@unique
class Socks5Command(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP = 3


@unique
class Socks5AddressType(IntEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


@unique
class Socks5ConnectionReply(IntEnum):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8
