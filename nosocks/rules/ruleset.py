from .rules import Rule
import random
import string
from ..consts import PROTOCOL, AUTH_METHOD, CMD, DEFAULT_NETWORK, RULE_ACTION
from ipaddress import IPv4Network


class Ruleset(Rule):

    def __init__(self, rule=None):
        super(Ruleset, self).init(action=RULE_ACTION.ALLOW, protocols=[PROTOCOL.SOCKS5],
                 auths=[AUTH_METHOD.NO_AUTHENTICATION],
                 commands=CMD.CONNECT, users=None,
                 sources=DEFAULT_NETWORK, destination=DEFAULT_NETWORK)

        self.rules = {}

    def add_rule(self, name=None, action=None, protocols=None,
                 auths=None, commands=None, users=None,
                 sources=None, destination=None):

        random_str = lambda n: ''.join([random.choice(string.lowercase) for i in range(n)])
        # Now to generate a random string of length 10

        name = name if name else random_str(8)

        action = action if action else self.action
        protocols = protocols if protocols else self.protocols
        auths = auths if auths else self.auths
        commands = commands if commands else self.commands
        users = users if users else self.users
        sources = sources if sources else self.sources
        destination = destination if destination else self.destination

        rule = Rule(action, protocols, auths, commands, users, sources, destination)

        self.rules[name] = rule

        return name