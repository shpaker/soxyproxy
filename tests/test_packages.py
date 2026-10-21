import asyncio
import typing
from ipaddress import IPv4Address, IPv6Address

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
        Socks5ConnectionRequest(client=mock_connection, data=data).command


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


class StreamConnection:
    """
    Connection over asyncio.StreamReader: data is a byte stream, not messages.
    """

    def __init__(
        self,
        data: bytes = b'',
        *,
        eof: bool = True,
    ) -> None:
        self.reader = asyncio.StreamReader()
        self.reader.feed_data(data)
        if eof:
            self.reader.feed_eof()

    async def read(self) -> bytes:
        return await self.reader.read(65536)

    async def readexactly(self, n: int) -> bytes:
        return await self.reader.readexactly(n)

    async def readuntil(self, separator: bytes) -> bytes:
        return await self.reader.readuntil(separator)

    async def rest(self) -> bytes:
        return await self.reader.read()


@pytest.mark.asyncio
async def test_socks5_greeting_and_auth_in_one_segment() -> None:
    conn = StreamConnection(b'\x05\x01\x02' + b'\x01\x04user\x06passwd')
    greeting = await Socks5GreetingRequest.from_client(conn)
    assert greeting.methods == [Socks5AuthMethod.USERNAME]
    auth = await Socks5AuthorizationRequest.from_client(conn)
    assert auth.username == 'user'
    assert auth.password == 'passwd'
    assert await conn.rest() == b''


@pytest.mark.asyncio
async def test_socks5_greeting_skips_unknown_methods() -> None:
    conn = StreamConnection(b'\x05\x03\x00\x03\x80')
    greeting = await Socks5GreetingRequest.from_client(conn)
    assert greeting.methods == [Socks5AuthMethod.NO_AUTHENTICATION]


@pytest.mark.asyncio
async def test_socks5_auth_non_ascii_username() -> None:
    username = 'юзер'.encode()
    conn = StreamConnection(bytes([1, len(username)]) + username + b'\x01p')
    auth = await Socks5AuthorizationRequest.from_client(conn)
    assert auth.username == 'юзер'
    assert auth.password == 'p'


@pytest.mark.parametrize(
    ('data', 'ip', 'domain_name', 'port'),
    [
        pytest.param(
            b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50',
            IPv4Address('127.0.0.1'),
            None,
            80,
            id='ipv4',
        ),
        pytest.param(
            b'\x05\x01\x00\x04' + IPv6Address('::1').packed + b'\x00\x50',
            IPv6Address('::1'),
            None,
            80,
            id='ipv6',
        ),
        pytest.param(
            b'\x05\x01\x00\x03\x0bexample.com\x01\xbb',
            None,
            'example.com',
            443,
            id='domain',
        ),
    ],
)
@pytest.mark.asyncio
async def test_socks5_connection_request_with_payload(
    data: bytes,
    ip: IPv4Address | IPv6Address | None,
    domain_name: str | None,
    port: int,
) -> None:
    conn = StreamConnection(data + b'GET / HTTP/1.1\r\n')
    request = await Socks5ConnectionRequest.from_client(conn)
    assert request.port == port
    assert request.domain_name == domain_name
    if ip is not None:
        assert request.destination == (ip, port)
    assert await conn.rest() == b'GET / HTTP/1.1\r\n'


@pytest.mark.asyncio
async def test_socks5_connection_request_unknown_address_type() -> None:
    conn = StreamConnection(b'\x05\x01\x00\x09\x01\x02\x03')
    request = await Socks5ConnectionRequest.from_client(conn)
    assert request.data == b'\x05\x01\x00\x09'


@pytest.mark.asyncio
async def test_socks4_request_with_payload() -> None:
    conn = StreamConnection(b'\x04\x01\x00\x50\x7f\x00\x00\x01user\x00payload')
    request = await Socks4Request.from_client(conn)
    assert request.destination.ip == IPv4Address('127.0.0.1')
    assert request.username == 'user'
    assert request.is_socks4a is False
    assert await conn.rest() == b'payload'


@pytest.mark.asyncio
async def test_socks4a_request() -> None:
    conn = StreamConnection(b'\x04\x01\x00\x50\x00\x00\x00\x01\x00example.com\x00payload')
    request = await Socks4Request.from_client(conn)
    assert request.is_socks4a is True
    assert request.username is None
    assert request.domain_name == 'example.com'
    assert await conn.rest() == b'payload'


def test_socks4_request_zero_address_is_not_socks4a(mock_connection: typing.Any) -> None:
    request = Socks4Request(client=mock_connection, data=b'\x04\x01\x00\x50\x00\x00\x00\x00\x00')
    assert request.is_socks4a is False


@pytest.mark.asyncio
async def test_fragmented_request() -> None:
    data = b'\x05\x01\x00\x03\x0bexample.com\x01\xbb'
    conn = StreamConnection(eof=False)
    task = asyncio.create_task(Socks5ConnectionRequest.from_client(conn))
    for byte in data:
        assert not task.done()
        conn.reader.feed_data(bytes([byte]))
        await asyncio.sleep(0)
    request = await asyncio.wait_for(task, timeout=1)
    assert request.domain_name == 'example.com'
    assert request.port == 443


@pytest.mark.parametrize(
    ('package', 'data'),
    [
        pytest.param(Socks4Request, b'\x04\x01\x00\x50\x7f\x00', id='socks4'),
        pytest.param(Socks4Request, b'\x04\x01\x00\x50\x7f\x00\x00\x01user', id='socks4 no null'),
        pytest.param(Socks5GreetingRequest, b'\x05\x02\x00', id='greeting'),
        pytest.param(Socks5AuthorizationRequest, b'\x01\x04us', id='auth'),
        pytest.param(Socks5ConnectionRequest, b'\x05\x01\x00\x01\x7f\x00', id='connection'),
        pytest.param(Socks5ConnectionRequest, b'', id='empty'),
    ],
)
@pytest.mark.asyncio
async def test_truncated_request(
    package: type[Socks4Request | Socks5GreetingRequest | Socks5AuthorizationRequest | Socks5ConnectionRequest],
    data: bytes,
) -> None:
    with pytest.raises(PackageError):
        await package.from_client(StreamConnection(data))


@pytest.mark.parametrize(
    ('package', 'data'),
    [
        pytest.param(Socks4Request, b'\x05\x01\x00', id='socks5 greeting to socks4'),
        pytest.param(Socks5GreetingRequest, b'\x04\x01\x00\x50', id='socks4 request to socks5'),
    ],
)
@pytest.mark.asyncio
async def test_wrong_version_fails_without_waiting_for_data(
    package: type[Socks4Request | Socks5GreetingRequest],
    data: bytes,
) -> None:
    with pytest.raises(PackageError):
        await asyncio.wait_for(package.from_client(StreamConnection(data, eof=False)), timeout=1)
