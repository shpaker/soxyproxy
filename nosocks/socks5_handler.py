from .auths.username_auth import UsernameAuth
from .auths.none_auth import NoneAuth
from .consts import AUTH_METHOD
from .messages.handshake_server import HandshakeServer
from .messages.reply_server import ReplyServer
from .consts import REP


class Socks5Handler:
    ''' SOCKS Protocol Version 5
        https://tools.ietf.org/html/rfc1928
    '''

    def __init__(self, reader, writer, auth_methods):
        self.SOCKS_VERSION = 5
        self.auth_methods = auth_methods
        self.reader = reader
        self.writer = writer

        self.client_ip, self.client_port = writer.get_extra_info('peername')

    def handshake(self, client_greeting):
        # todo except return nothing
        auth_method = self.choose_auth_method(client_greeting.methods)

        server_greeting = HandshakeServer(auth_method)

        self.writer.write(server_greeting.to_bytes())

        return server_greeting

    def process_request(self, client_request):
        server_replay = ReplyServer(REP.SUCCEEDED, client_request.dst_addr, client_request.dst_port)

        response = server_replay.to_bytes()
        self.writer.write(response)

        return server_replay

    def choose_auth_method(self, client_methods):
        for auth_method in client_methods:
            if auth_method in self.auth_methods:

                return auth_method
