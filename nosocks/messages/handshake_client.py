from ..consts import AUTH_METHOD
from ..consts import get_enum_member


class HandshakeClient:
    '''
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
    '''
    def __init__(self, raw_bytes):
        self.ver = raw_bytes[0]
        self.nmethods = raw_bytes[1]
        self.methods = [get_enum_member(AUTH_METHOD, id) for id in list(raw_bytes[2:])]


    def __str__(self):
        output = 'Client greeting: ver = {}, nmethods = {}, methods = {}'
        methods_str ='[ ' + ', '.join([m.name for m in self.methods]) + ' ]'

        return output.format(self.ver, self.nmethods, methods_str)
