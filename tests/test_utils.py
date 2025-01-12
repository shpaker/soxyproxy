from ipaddress import IPv4Address, IPv4Network

import pytest

from soxy._errors import PackageError  # Fixed error name
from soxy._types import Address, SocksVersions
from soxy._utils import check_protocol_version, match_addresses, port_from_bytes, port_to_bytes


def test_match_addresses() -> None:
    address = Address(ip=IPv4Address('192.168.1.1'), port=8080)
    ip_address = IPv4Address('192.168.1.1')
    ip_network = IPv4Network('192.168.1.0/24')
    assert match_addresses(address, ip_address)
    assert match_addresses(address, ip_network)
    assert not match_addresses(address, IPv4Address('10.0.0.1'))
    assert not match_addresses(address, IPv4Network('10.0.0.0/24'))


def test_port_from_bytes() -> None:
    assert port_from_bytes(b'\x1f\x90') == 8080
    assert port_from_bytes(b'\x00\x50') == 80


def test_port_to_bytes() -> None:
    assert port_to_bytes(8080) == b'\x1f\x90'
    assert port_to_bytes(80) == b'\x00\x50'


def test_check_protocol_version() -> None:
    with pytest.raises(PackageError):
        check_protocol_version(b'', SocksVersions.SOCKS5)
    with pytest.raises(PackageError):
        check_protocol_version(b'\x04', SocksVersions.SOCKS5)
    check_protocol_version(b'\x05', SocksVersions.SOCKS5)
