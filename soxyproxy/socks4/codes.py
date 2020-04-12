from enum import Enum, unique


@unique
class ConnectionTypes(Enum):
    CONNECT = 1
    BIND = 2


class ReplyCodes(Enum):

    granted = 0x5A  # Request granted
    rejected = 0x5B  # Request rejected or failed

    identd_not_reachable = 0x5C  # Request failed because client is not running identd (or not reachable from server)
    identd_rejected = 0x5D  # Request failed because client's identd could not confirm the user ID in the request
