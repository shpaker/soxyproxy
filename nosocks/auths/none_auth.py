from .auth import Auth
from ..consts import AUTH_METHOD


class NoneAuth(Auth):

    def __init__(self):
        super(NoneAuth, self).__init__(AUTH_METHOD.NO_AUTHENTICATION)
