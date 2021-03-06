from enum import Enum, unique

__all__ = ['Socks4Commands', 'Socks4Replies']


@unique
class Socks4Commands(Enum):
    CONNECT = 1
    BIND = 2


class Socks4Replies(Enum):
    GRANTED = 0x5A  # Request granted
    REJECTED = 0x5B  # Request rejected or failed
    IDENTD_NOT_REACHABLE = 0x5C  # Request failed because client is not running identd (or not reachable from server)
    IDENTD_REJECTED = 0x5D  # Request failed because client's identd could not confirm the user ID in the request
