from .auth import Auth
from ..consts import AUTH_STATUS
from ..consts import METHOD
from ..messages.auth_username_reply import AuthUsernameReply


class BasicAuth(Auth):

    def __init__(self, auth_message):
        super(BasicAuth, self).__init__(METHOD.USERNAME_PASSWORD)

        self.auth_message = auth_message

    def auth(self, reader, writer, username, password):

        if self.auth_message.uname == username and self.auth_message.passwd == password:
            reply = AuthUsernameReply(AUTH_STATUS.SUCCESS)
        else:
            reply = AuthUsernameReply(AUTH_STATUS.FAIL)

        writer.write(reply.to_bytes())

        return reply
