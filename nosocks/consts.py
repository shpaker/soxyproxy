from enum import Enum, unique


SOCKS_PORT = 1080

IPv4_OCTET_LENGTH = 4
IPv6_OCTET_LENGTH = 16


@unique
class METHOD(Enum):
    NO_AUTHENTICATION = 0
    GSSAPI = 1
    USERNAME_PASSWORD = 2
    NO_ACCEPTABLE = 255

@unique
class ATYP(Enum):
    IPv4 = 1
    DOMAIN = 3
    IPv6 = 4

@unique
class CMD(Enum):
    CONNECT = 1
    BIND = 2
    UDP = 3

@unique
class REP(Enum):
    SUCCEEDED = 0
    GENERAL_SOCKS_SERVER_FAILURE = 1
    CONNECTION_NOT_ALLOWED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8

def get_enum_member(enum_members, unique_value):
    for m in enum_members:
        if m.value == unique_value:
            return m