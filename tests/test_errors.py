from ipaddress import IPv4Address

from soxy._errors import (
    AuthorizationError,
    ConfigError,
    PackageError,
    ProtocolError,
    RejectError,
    ResolveDomainError,
)
from soxy._types import Address


def test_package_error() -> None:
    data = b'test data'
    error = PackageError(data)
    assert error.data == data
    assert isinstance(error, ValueError)


def test_protocol_error() -> None:
    error = ProtocolError()
    assert isinstance(error, Exception)


def test_resolve_domain_error() -> None:
    domain = 'example.com'
    port = 80
    error = ResolveDomainError(domain, port)
    assert error.domain == domain
    assert error.port == port
    assert isinstance(error, ProtocolError)


def test_authorization_error() -> None:
    username = 'test_user'
    error = AuthorizationError(username)
    assert error.username == username
    assert isinstance(error, ProtocolError)


def test_reject_error_with_address() -> None:
    address = Address(ip=IPv4Address('127.0.0.1'), port=8080)
    error = RejectError(address)
    assert error.address == address
    assert isinstance(error, ProtocolError)


def test_reject_error_without_address() -> None:
    error = RejectError()
    assert error.address.ip == IPv4Address(0)
    assert error.address.port == 0
    assert isinstance(error, ProtocolError)


def test_config_error() -> None:
    section = 'proxy'
    message = 'test message'
    error = ConfigError(section, message)
    assert str(error) == f'[{section}] {message}'
    assert isinstance(error, ValueError)


def test_config_error_default_message() -> None:
    section = 'transport'
    error = ConfigError(section)
    assert str(error) == f'[{section}] incorrect configuration'
    assert isinstance(error, ValueError)
