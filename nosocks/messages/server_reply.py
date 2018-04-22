import ipaddress
from ..consts import get_enum_member
from ..consts import CMD, ATYP


class ServerReply:
    '''
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

     Where:


          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order
    '''
    def to_bytes(self):
        PORT_BYTES_LENGTH = 2

        response = bytes([self.ver, self.rep.value, self.rsv, self.atyp.value])

        if self.atyp == ATYP.IPv4:
            ip = self.bnd_addr.packed
        elif self.atyp == ATYP.IPv6:
            ip = self.bnd_addr.packed

        port = int.to_bytes(self.bnd_port, PORT_BYTES_LENGTH, 'big')

        return response + ip + port

    def __init__(self, rep, bnd_addr, bnd_port):
        self.ver = 5
        self.rep = rep
        self.rsv = 0

        self.atyp = ATYP.IPv4 if bnd_addr.version == 4 else ATYP.IPv6
        self.bnd_addr = bnd_addr
        self.bnd_port = bnd_port


    def __str__(self):
        output = 'Server replay: ver = {}, rep = {}, rsv = {}, ' \
                 'atyp = {}, bnd_addr = {}, bnd_port = {}'

        return output.format(self.ver, self.rep.name, self.rsv, self.atyp.name, self.bnd_addr, self.bnd_port)
