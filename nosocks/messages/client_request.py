from ipaddress import IPv4Address, IPv6Address, IPV4LENGTH, IPV6LENGTH
from ..consts import get_enum_member
from ..consts import CMD, ATYP


class ClientRequest():
    '''
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

    Where:

    *  VER    protocol version: X'05'
    *  CMD
        *  CONNECT X'01'
        *  BIND X'02'
        *  UDP ASSOCIATE X'03'
    *  RSV    RESERVED
    *  ATYP   address type of following address
        *  IP V4 address: X'01'
        *  DOMAINNAME: X'03'
        *  IP V6 address: X'04'
    *  DST.ADDR       desired destination address
    *  DST.PORT       desired destination port in network octet order
    '''

    def __init__(self, raw_bytes):

        self.ver = raw_bytes[0]
        self.cmd = get_enum_member(CMD, raw_bytes[1])
        self.rsv = raw_bytes[2]  # todo: should be zero
        self.atyp = get_enum_member(ATYP, raw_bytes[3])
        self.dst_addr = None
        self.dst_port = int.from_bytes(raw_bytes[-2:], byteorder='big')

        OCTET_LENGTH = 8

        if self.atyp == ATYP.IPv4:
            addr_length = IPV4LENGTH//OCTET_LENGTH
            self.dst_addr = IPv4Address(raw_bytes[4:4+addr_length])

        if self.atyp == ATYP.IPv6:
            addr_length = IPV6LENGTH//OCTET_LENGTH
            self.dst_addr = IPv6Address(raw_bytes[4:4+addr_length])

        if self.atyp == ATYP.DOMAIN:
            # todo add domain resolving
            pass


    def __str__(self):
        output = 'Client request: ver = {}, cmd = {}, rsv = {}, atyp = {}, ' \
                 'dst_addr = {}, dst_port = {}'

        return output.format(self.ver, self.cmd.name, self.rsv, self.atyp.name, self.dst_addr, self.dst_port)
