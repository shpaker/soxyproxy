from .auth import Auth
from ..consts import METHOD

class BasicAuth(Auth):

    def __init__(self):
        super(BasicAuth, self).__init__(METHOD.USERNAME_PASSWORD)

    def auth(self):
        return True
