class Auth:
    '''
    X'00' NO AUTHENTICATION REQUIRED
    X'01' GSSAPI
    X'02' USERNAME/PASSWORD
    X'03' to X'7F' IANA ASSIGNED
    X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    X'FF' NO ACCEPTABLE METHODS
    '''

    def __init__(self, method):
        self.SOCKS_VERSION = 5
        self.method = method


    def auth(self, reader, writer):
        raise NotImplemented

    def __str__(self):
        return 'Authentication method {} - {}'.format(self.method.value,
                                                      self.method.name)
