from .auths.basic_auth import BasicAuth
from .auths.none_auth import NoneAuth
from .consts import METHOD
from .messages.server_greeting import ServerGreeting
from .messages.server_reply import ServerReply
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

    def greet(self, client_greeting):
        # todo except return nothing
        auth = self.choose_auth_method(client_greeting.methods)

        server_greeting = ServerGreeting(auth.method)

        self.writer.write(server_greeting.to_bytes())

        return server_greeting

    def process_request(self, client_request):
        server_replay = ServerReply(REP.SUCCEEDED, client_request.dst_addr, client_request.dst_port)

        response = server_replay.to_bytes()
        self.writer.write(response)

        return server_replay

    def choose_auth_method(self, client_methods):
        for auth_id in client_methods:
            if auth_id in self.auth_methods:

                # todo: validate ID
                auth = None

                if auth_id == METHOD.NO_AUTHENTICATION:
                    auth = NoneAuth()

                if auth_id == METHOD.USERNAME_PASSWORD:
                    auth = BasicAuth()

                return auth
