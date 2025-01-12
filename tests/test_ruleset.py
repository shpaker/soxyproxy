from ipaddress import IPv4Address, IPv4Network
from unittest.mock import Mock

from soxy._ruleset import ConnectingRule, ProxyingRule, Ruleset
from soxy._types import Address, Connection


def test_connecting_rule() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    rule = ConnectingRule(from_addresses=IPv4Network('0.0.0.0/0'))
    assert rule(connection) is True


def test_connecting_rule_negative() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    rule = ConnectingRule(from_addresses=IPv4Network('10.0.0.0/8'))
    assert rule(connection) is False


def test_proxying_rule() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    target_address = Address(IPv4Address('192.168.1.2'), 1234)
    rule = ProxyingRule(from_addresses=IPv4Network('192.168.1.0/24'), to_addresses=IPv4Network('192.168.1.2/32'))
    assert rule(connection, target_address, None) is True


def test_proxying_rule_negative() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    target_address = Address(IPv4Address('192.168.1.2'), 1234)
    rule = ProxyingRule(from_addresses=IPv4Network('10.0.0.0/8'), to_addresses=IPv4Network('192.168.1.2/32'))
    assert rule(connection, target_address, None) is False


def test_ruleset_negative() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    target_address = Address(IPv4Address('192.168.1.2'), 1234)
    allow_connecting_rule = ConnectingRule(from_addresses=IPv4Network('10.0.0.0/8'))
    block_connecting_rule = ConnectingRule(from_addresses=IPv4Network('192.168.1.0/24'))
    allow_proxying_rule = ProxyingRule(
        from_addresses=IPv4Network('10.0.0.0/8'), to_addresses=IPv4Network('192.168.1.2/32')
    )
    block_proxying_rule = ProxyingRule(
        from_addresses=IPv4Network('192.168.1.0/24'), to_addresses=IPv4Network('192.168.1.2/32')
    )

    ruleset = Ruleset(
        allow_connecting_rules=[allow_connecting_rule],
        allow_proxying_rules=[allow_proxying_rule],
        block_connecting_rules=[block_connecting_rule],
        block_proxying_rules=[block_proxying_rule],
    )

    assert ruleset.should_allow_connecting(connection) is False
    assert ruleset.should_allow_proxying(connection, target_address, None) is False


def test_ruleset_positive() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('10.0.0.1'), 12345)
    target_address = Address(IPv4Address('192.168.1.2'), 1234)

    allow_connecting_rule = ConnectingRule(from_addresses=IPv4Network('0.0.0.0/0'))
    allow_proxying_rule = ProxyingRule(
        from_addresses=IPv4Network('10.0.0.0/8'), to_addresses=IPv4Network('192.168.1.2/32')
    )

    ruleset = Ruleset(
        allow_connecting_rules=[allow_connecting_rule],
        allow_proxying_rules=[allow_proxying_rule],
        block_connecting_rules=[],
        block_proxying_rules=[],
    )

    assert ruleset.should_allow_connecting(connection) is True
    assert ruleset.should_allow_proxying(connection, target_address, None) is True


def test_ruleset_empty() -> None:
    connection = Mock(spec=Connection)
    connection.address = Address(IPv4Address('192.168.1.1'), 12345)
    target_address = Address(IPv4Address('192.168.1.2'), 1234)

    ruleset = Ruleset(
        allow_connecting_rules=[],
        allow_proxying_rules=[],
        block_connecting_rules=[],
        block_proxying_rules=[],
    )

    assert ruleset.should_allow_connecting(connection) is False
    assert ruleset.should_allow_proxying(connection, target_address, None) is False
