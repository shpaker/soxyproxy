from ..consts import AUTH_METHOD, PROTOCOL, CMD, RULE_ACTION, DEFAULT_NETWORK


class Rule:
    def __init__(self, action, protocols, auths, commands, users, sources, destination):

        self.action = action
        self.protocols = protocols
        self.auths = auths
        self.commands = commands
        self.users = users
        self.sources = sources
        self.destination = destination

        # self.ports = None
        # self.days = None
        # self.time = None