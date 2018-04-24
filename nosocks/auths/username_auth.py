from .auth import Auth
from ..consts import AUTH_STATUS
from ..consts import AUTH_METHOD
from ..messages.username_auth_server import UsernameAuthServer


class UsernameAuth(Auth):

    def __init__(self, auth_message):
        super(UsernameAuth, self).__init__(AUTH_METHOD.USERNAME_PASSWORD)

        self.auth_message = auth_message

    def auth(self, reader, writer, username, password):

        if self.auth_message.uname == username and self.auth_message.passwd == password:
            reply = UsernameAuthServer(AUTH_STATUS.SUCCESS)
        else:
            reply = UsernameAuthServer(AUTH_STATUS.FAIL)

        writer.write(reply.to_bytes())

        return reply
