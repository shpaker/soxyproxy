import typing
from ipaddress import IPv4Address

import pytest

from soxy import PackageError
from soxy._packages import (
    Socks4Request,
    Socks4Response,
    Socks5AuthorizationRequest,
    Socks5AuthorizationResponse,
    Socks5ConnectionRequest,
    Socks5ConnectionResponse,
    Socks5GreetingRequest,
    Socks5GreetingResponse,
)
from soxy._types import (
    Socks4Command,
    Socks4Reply,
    Socks5AddressType,
    Socks5AuthMethod,
    Socks5Command,
    Socks5ConnectionReply,
    SocksVersions,
)


@pytest.fixture
def mock_connection() -> typing.Any:
    class MockConnection:
        async def read(self) -> bytes:
            return b'\x04\x01\x00\x50\x7f\x00\x00\x01\x00'

        async def write(self, data) -> None:
            self.data = data

    return MockConnection()


def test_socks4_request(mock_connection: typing.Any) -> None:
    data = b'\x04\x01\x00\x50\x7f\x00\x00\x01\x00'
    request = Socks4Request(client=mock_connection, data=data)
    assert request.socks_version == SocksVersions.SOCKS4
    assert request.command == Socks4Command.CONNECT
    assert request.destination.ip == IPv4Address('127.0.0.1')
    assert request.destination.port == 80


def test_socks4_request_invalid_data(mock_connection: typing.Any) -> None:
    data = b'\x05\x01\x00\x50\x7f\x00\x00\x01\x00'  # Invalid SOCKS version
    with pytest.raises(PackageError):
        Socks4Request(client=mock_connection, data=data)


def test_socks4_request_invalid_command(mock_connection: typing.Any) -> None:
    data = b'\x04\xff\x00\x50\x7f\x00\x00\x01\x00'  # Invalid command
    with pytest.raises(PackageError):
        Socks4Request(client=mock_connection, data=data).command


def test_socks4_request_invalid_destination(mock_connection: typing.Any) -> None:
    data = b'\x04\x01\x00\x50\x7f\x00\x00'  # Incomplete destination
    with pytest.raises(PackageError):
        Socks4Request(client=mock_connection, data=data)


def test_socks4_request_invalid_username(mock_connection: typing.Any) -> None:
    data = b'\x04\x01\x00\x50\x7f\x00\x00\x01\x00\xff'  # Invalid username encoding
    with pytest.raises(PackageError):
        Socks4Request(client=mock_connection, data=data)


def test_socks4_response(mock_connection: typing.Any) -> None:
    response = Socks4Response(client=mock_connection, reply=Socks4Reply.GRANTED)
    assert response.data == b'\x00\x5a\x00\x00\x00\x00\x00\x01'


def test_socks5_greeting_request(mock_connection: typing.Any) -> None:
    data = b'\x05\x01\x00'
    request = Socks5GreetingRequest(client=mock_connection, data=data)
    assert request.socks_version == SocksVersions.SOCKS5
    assert request.methods == [Socks5AuthMethod.NO_AUTHENTICATION]


def test_socks5_greeting_request_invalid_data(mock_connection: typing.Any) -> None:
    data = b'\x05\x02\x00'  # Invalid methods number
    with pytest.raises(PackageError):
        Socks5GreetingRequest(client=mock_connection, data=data)


def test_socks5_greeting_response(mock_connection: typing.Any) -> None:
    response = Socks5GreetingResponse(method=Socks5AuthMethod.NO_AUTHENTICATION, client=mock_connection)
    assert response.data == b'\x05\x00'


def test_socks5_authorization_request(mock_connection: typing.Any) -> None:
    data = b'\x01\x04user\x06passwd'
    request = Socks5AuthorizationRequest(client=mock_connection, data=data)
    assert request.username == 'user'
    assert request.password == 'passwd'


def test_socks5_authorization_request_invalid_data(mock_connection: typing.Any) -> None:
    data = b'\x01\x04user'  # Incomplete data
    with pytest.raises(PackageError):
        Socks5AuthorizationRequest(client=mock_connection, data=data)


def test_socks5_authorization_request_invalid_username(mock_connection: typing.Any) -> None:
    data = b'\x01\xffuser\x06passwd'  # Invalid username length
    with pytest.raises(PackageError):
        Socks5AuthorizationRequest(client=mock_connection, data=data)


def test_socks5_authorization_request_invalid_password(mock_connection: typing.Any) -> None:
    data = b'\x01\x04user\xffpasswd'  # Invalid password length
    with pytest.raises(PackageError):
        Socks5AuthorizationRequest(client=mock_connection, data=data)


def test_socks5_authorization_response(mock_connection: typing.Any) -> None:
    response = Socks5AuthorizationResponse(is_success=True, client=mock_connection)
    assert response.data == b'\x01\x00'


def test_socks5_authorization_response_failure(mock_connection: typing.Any) -> None:
    response = Socks5AuthorizationResponse(is_success=False, client=mock_connection)
    assert response.data == b'\x01\x01'


def test_socks5_connection_request(mock_connection: typing.Any) -> None:
    data = b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50'
    request = Socks5ConnectionRequest(client=mock_connection, data=data)
    assert request.socks_version == SocksVersions.SOCKS5
    assert request.command == Socks5Command.CONNECT
    assert request.address_type == Socks5AddressType.IPv4
    assert request.destination.ip == IPv4Address('127.0.0.1')
    assert request.destination.port == 80


def test_socks5_connection_request_invalid_data(mock_connection: typing.Any) -> None:
    data = b'\x05\x01\x00\x04\x7f\x00\x00\x01\x00\x50'  # Invalid address type
    with pytest.raises(PackageError):
        Socks5ConnectionRequest(client=mock_connection, data=data).destination


def test_socks5_connection_request_invalid_command(mock_connection: typing.Any) -> None:
    data = b'\x05\xff\x00\x01\x7f\x00\x00\x01\x00\x50'  # Invalid command
    with pytest.raises(PackageError):
        Socks5ConnectionRequest(client=mock_connection, data=data)


def test_socks5_connection_request_invalid_address_type(mock_connection: typing.Any) -> None:
    data = b'\x05\x01\x00\xff\x7f\x00\x00\x01\x00\x50'  # Invalid address type
    with pytest.raises(PackageError):
        Socks5ConnectionRequest(client=mock_connection, data=data).address_type


def test_socks5_connection_response(mock_connection: typing.Any) -> None:
    response = Socks5ConnectionResponse(
        client=mock_connection,
        reply=Socks5ConnectionReply.SUCCEEDED,
        destination=IPv4Address('127.0.0.1'),
        port=80,
    )
    assert response.data == b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50'
