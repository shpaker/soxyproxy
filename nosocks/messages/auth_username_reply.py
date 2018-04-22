class AuthUsernameReply():
    '''
    +----+--------+
    |VER | STATUS |
    +----+--------+
    | 1  |   1    |
    +----+--------+
    '''
    def __init__(self, status):
        self.ver = 5
        self.status = status

    def to_bytes(self):
        return bytes([self.ver, self.status.value])

    def __str__(self):
        output = 'Auth reply: ver = {}, method = {}'

        return output.format(self.ver, self.status.name)
