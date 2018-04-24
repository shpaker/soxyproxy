class UsernameAuthClient:
    '''
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
    '''
    def __init__(self, raw_bytes):
        self.ver = raw_bytes[0]

        self.ulen = raw_bytes[1]
        self.uname = raw_bytes[2:2 + self.ulen].decode()

        self.plen = raw_bytes[2 + self.ulen]
        self.passwd = raw_bytes[3 + self.ulen:3 + self.ulen + self.plen].decode()

    def __str__(self):
        output = 'Auth username: ver = {}, ulen = {}, uname = {}, plen = {}, passwd = {}'

        return output.format(self.ver, self.ulen, self.uname, self.plen, self.passwd)
