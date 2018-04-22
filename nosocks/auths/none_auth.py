from .auth import Auth
from ..consts import METHOD


class NoneAuth(Auth):

    def __init__(self):
        super(NoneAuth, self).__init__(METHOD.NO_AUTHENTICATION)
