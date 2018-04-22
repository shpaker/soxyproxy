class ServerGreeting():
    '''
    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
    '''
    def __init__(self, method):
        self.ver = 5
        self.method = method

    def to_bytes(self):
        return bytes([self.ver, self.method.value])

    def __str__(self):
        output = 'Server greeting: ver = {}, method = {}'

        return output.format(self.ver, self.method.name)