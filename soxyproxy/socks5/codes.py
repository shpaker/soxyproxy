from enum import unique, Enum

RESERVED_VALUE = 0
USERNAME_AUTH_VERSION = 1
ADDRESS_PORT_BYTES_LENGTH = 2
ADDRESS_PORT_BYTE_ORDER = 'big'
ADDRESS_OCTET_LENGTH = 8


@unique
class AuthMethods(Enum):
    NO_AUTHENTICATION = 0
    GSSAPI = 1
    USERNAME = 2
    NO_ACCEPTABLE = 255


@unique
class AuthStatus(Enum):
    SUCCESS = 0
    FAIL = 1


@unique
class ConnectionTypes(Enum):
    CONNECT = 1
    BIND = 2
    UDP = 3


@unique
class AddressTypes(Enum):
    IPv4 = 1
    DOMAIN = 3
    IPv6 = 4


@unique
class ReplyCodes(Enum):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8
