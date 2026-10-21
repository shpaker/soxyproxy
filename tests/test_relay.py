import asyncio
import contextlib
import ipaddress
import socket
import struct
import typing
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

import soxy
from soxy._tcp import TCPConnection
from soxy._types import Socks4Reply, Socks5ConnectionReply

Handler: typing.TypeAlias = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]

GREETING = b'\x05\x01\x00'


def allow_all() -> soxy.Ruleset:
    networks = [ipaddress.IPv4Network('0.0.0.0/0'), ipaddress.IPv6Network('::/0')]
    return soxy.Ruleset(
        allow_connecting_rules=[soxy.ConnectingRule(from_addresses=network) for network in networks],
        allow_proxying_rules=[
            soxy.ProxyingRule(from_addresses=from_, to_addresses=to_) for from_ in networks for to_ in networks
        ],
    )


def ipv6_available() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(('::1', 0))
    except OSError:
        return False
    return True


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@contextlib.asynccontextmanager
async def run_proxy(
    protocol: soxy.Socks4 | soxy.Socks5 | None = None,
    ruleset: soxy.Ruleset | None = None,
    host: str = '127.0.0.1',
    **transport_kwargs: float,
) -> AsyncIterator[int]:
    async with soxy.Proxy(
        protocol=protocol or soxy.Socks5(),
        ruleset=ruleset or allow_all(),
        transport=soxy.TcpTransport(host=host, port=0, **transport_kwargs),  # type: ignore[arg-type]
    ) as proxy:
        yield proxy.sockets[0].getsockname()[1]


@contextlib.asynccontextmanager
async def run_upstream(
    handler: Handler,
    host: str = '127.0.0.1',
) -> AsyncIterator[int]:
    server = await asyncio.start_server(handler, host, 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        server.abort_clients()
        await server.wait_closed()


async def close_writer(
    writer: asyncio.StreamWriter,
) -> None:
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def echo(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    with contextlib.suppress(OSError):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    await close_writer(writer)


def socks5_request(
    host: str,
    port: int,
    command: int = 1,
) -> bytes:
    ip = ipaddress.ip_address(host)
    address_type = 1 if ip.version == 4 else 4  # noqa: PLR2004
    return bytes([5, command, 0, address_type]) + ip.packed + struct.pack('!H', port)


async def read_socks5_reply(
    reader: asyncio.StreamReader,
) -> tuple[int, ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    header = await reader.readexactly(4)
    match header[3]:
        case 1:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(await reader.readexactly(4))
        case 4:
            ip = ipaddress.IPv6Address(await reader.readexactly(16))
        case _:
            pytest.fail(f'unexpected address type in reply: {header!r}')
    (port,) = struct.unpack('!H', await reader.readexactly(2))
    return header[1], ip, port


async def socks5_open(
    proxy_port: int,
    host: str,
    port: int,
    proxy_host: str = '127.0.0.1',
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, int]:
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    writer.write(GREETING)
    assert await reader.readexactly(2) == b'\x05\x00'
    writer.write(socks5_request(host, port))
    reply, _, _ = await read_socks5_reply(reader)
    return reader, writer, reply


@pytest.mark.asyncio
async def test_socks5_fragmented_handshake() -> None:
    async with run_upstream(echo) as upstream_port, run_proxy() as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        for byte in GREETING + socks5_request('127.0.0.1', upstream_port):
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0.005)
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, _, _ = await read_socks5_reply(reader)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        writer.write(b'ping')
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks5_handshake_and_payload_in_one_segment() -> None:
    async with run_upstream(echo) as upstream_port, run_proxy() as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + socks5_request('127.0.0.1', upstream_port) + b'ping')
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, _, _ = await read_socks5_reply(reader)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks4_request_and_payload_in_one_segment() -> None:
    async with run_upstream(echo) as upstream_port, run_proxy(protocol=soxy.Socks4()) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(
            b'\x04\x01' + struct.pack('!H', upstream_port) + ipaddress.IPv4Address('127.0.0.1').packed + b'\x00ping',
        )
        reply = await reader.readexactly(8)
        assert reply[1] == Socks4Reply.GRANTED
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks5_success_reply_contains_bound_address() -> None:
    peers: list[tuple[str, int]] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peers.append(writer.get_extra_info('peername'))
        await echo(reader, writer)

    async with run_upstream(handler) as upstream_port, run_proxy() as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + socks5_request('127.0.0.1', upstream_port))
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, ip, port = await read_socks5_reply(reader)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        assert (str(ip), port) == peers[0][:2]
        await close_writer(writer)


@pytest.mark.skipif(not ipv6_available(), reason='IPv6 is not available')
@pytest.mark.asyncio
async def test_socks5_ipv6() -> None:
    async with run_upstream(echo, host='::1') as upstream_port, run_proxy(host='::1') as proxy_port:
        reader, writer, reply = await socks5_open(proxy_port, '::1', upstream_port, proxy_host='::1')
        assert reply == Socks5ConnectionReply.SUCCEEDED
        writer.write(b'ping')
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_half_close() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read()
        writer.write(b'got:' + data)
        await writer.drain()
        await close_writer(writer)

    async with run_upstream(handler) as upstream_port, run_proxy() as proxy_port:
        reader, writer, reply = await socks5_open(proxy_port, '127.0.0.1', upstream_port)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        writer.write(b'hello')
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=1) == b'got:hello'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_full_duplex() -> None:
    # upstream sends everything before it starts reading, so the proxy must
    # keep forwarding upstream data while the client data is backpressured
    size = 16 * 1024 * 1024
    payload = b'x' * size

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(payload)
        await writer.drain()
        assert await reader.readexactly(size) == payload
        await close_writer(writer)

    async def send(writer: asyncio.StreamWriter) -> None:
        writer.write(payload)
        await writer.drain()

    async with run_upstream(handler) as upstream_port, run_proxy() as proxy_port:
        reader, writer, reply = await socks5_open(proxy_port, '127.0.0.1', upstream_port)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        async with asyncio.timeout(20):
            _, received = await asyncio.gather(send(writer), reader.readexactly(size))
        assert received == payload
        await close_writer(writer)


@pytest.mark.asyncio
async def test_handshake_timeout() -> None:
    async with run_proxy(handshake_timeout=0.2) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        assert await asyncio.wait_for(reader.read(), timeout=2) == b''
        await close_writer(writer)


@pytest.mark.asyncio
async def test_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def slow_open(cls: type[TCPConnection], host: str, port: int) -> TCPConnection:  # noqa: ARG001
        await asyncio.sleep(10)
        raise AssertionError

    monkeypatch.setattr(TCPConnection, 'open', classmethod(slow_open))
    async with run_proxy(connect_timeout=0.2) as proxy_port:
        _, writer, reply = await asyncio.wait_for(
            socks5_open(proxy_port, '127.0.0.1', 9),
            timeout=2,
        )
        assert reply == Socks5ConnectionReply.HOST_UNREACHABLE
        await close_writer(writer)


@pytest.mark.asyncio
async def test_connection_refused() -> None:
    async with run_proxy() as proxy_port:
        _, writer, reply = await socks5_open(proxy_port, '127.0.0.1', free_port())
        assert reply == Socks5ConnectionReply.CONNECTION_REFUSED
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks5_ruleset_reject() -> None:
    ruleset = soxy.Ruleset(
        allow_connecting_rules=[soxy.ConnectingRule(from_addresses=ipaddress.IPv4Network('0.0.0.0/0'))],
        allow_proxying_rules=[],
    )
    async with run_upstream(echo) as upstream_port, run_proxy(ruleset=ruleset) as proxy_port:
        reader, writer, reply = await socks5_open(proxy_port, '127.0.0.1', upstream_port)
        assert reply == Socks5ConnectionReply.CONNECTION_NOT_ALLOWED_BY_RULESET
        assert await asyncio.wait_for(reader.read(), timeout=1) == b''
        await close_writer(writer)


@pytest.mark.parametrize(
    ('request_data', 'expected_reply'),
    [
        pytest.param(
            socks5_request('127.0.0.1', 80, command=2),
            Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
            id='bind',
        ),
        pytest.param(
            socks5_request('127.0.0.1', 80, command=3),
            Socks5ConnectionReply.COMMAND_NOT_SUPPORTED,
            id='udp associate',
        ),
        pytest.param(
            b'\x05\x01\x00\x09',
            Socks5ConnectionReply.ADDRESS_TYPE_NOT_SUPPORTED,
            id='unknown address type',
        ),
        pytest.param(
            b'\x05\x01\x00\x03\x0bexample.com\x00\x50',
            Socks5ConnectionReply.ADDRESS_TYPE_NOT_SUPPORTED,
            id='domain without resolver',
        ),
    ],
)
@pytest.mark.asyncio
async def test_socks5_unsupported_request(request_data: bytes, expected_reply: int) -> None:
    async with run_proxy() as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + request_data)
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, _, _ = await asyncio.wait_for(read_socks5_reply(reader), timeout=1)
        assert reply == expected_reply
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks5_no_acceptable_methods() -> None:
    protocol = soxy.Socks5(auther=lambda username, password: True)  # noqa: ARG005
    async with run_proxy(protocol=protocol) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING)
        assert await asyncio.wait_for(reader.read(), timeout=1) == b'\x05\xff'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_shutdown_with_active_session() -> None:
    async with run_upstream(echo) as upstream_port:
        async with asyncio.timeout(3):
            async with soxy.Proxy(
                protocol=soxy.Socks5(),
                ruleset=allow_all(),
                transport=soxy.TcpTransport(port=0, shutdown_timeout=1),
            ) as proxy:
                serve_task = asyncio.create_task(proxy.serve_forever())
                proxy_port = proxy.sockets[0].getsockname()[1]
                reader, writer, reply = await socks5_open(proxy_port, '127.0.0.1', upstream_port)
                assert reply == Socks5ConnectionReply.SUCCEEDED
                writer.write(b'ping')
                assert await reader.readexactly(4) == b'ping'
                serve_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await serve_task
        assert await asyncio.wait_for(reader.read(), timeout=1) == b''
        await close_writer(writer)


def socks5_domain_request(
    domain_name: str,
    port: int,
) -> bytes:
    return b'\x05\x01\x00\x03' + bytes([len(domain_name)]) + domain_name.encode() + struct.pack('!H', port)


@pytest.mark.asyncio
async def test_socks5h_system_resolver() -> None:
    protocol = soxy.Socks5(resolver=soxy.SystemResolver())
    async with run_upstream(echo) as upstream_port, run_proxy(protocol=protocol) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + socks5_domain_request('localhost', upstream_port) + b'ping')
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, _, _ = await read_socks5_reply(reader)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks4a_system_resolver() -> None:
    protocol = soxy.Socks4(resolver=soxy.SystemResolver())
    async with run_upstream(echo) as upstream_port, run_proxy(protocol=protocol) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(b'\x04\x01' + struct.pack('!H', upstream_port) + b'\x00\x00\x00\x01\x00localhost\x00ping')
        reply = await reader.readexactly(8)
        assert reply[1] == Socks4Reply.GRANTED
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.skipif(not ipv6_available(), reason='IPv6 is not available')
@pytest.mark.asyncio
async def test_socks5h_ipv6_only_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    async def getaddrinfo(host: str, *args: object, **kwargs: object) -> list[typing.Any]:  # noqa: ARG001
        assert host == 'ipv6only.test'
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0))]

    # numeric hosts don't go through getaddrinfo in asyncio, so only the resolver is affected
    monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', getaddrinfo)
    protocol = soxy.Socks5(resolver=soxy.SystemResolver())
    async with run_upstream(echo, host='::1') as upstream_port, run_proxy(protocol=protocol) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + socks5_domain_request('ipv6only.test', upstream_port))
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, ip, _ = await read_socks5_reply(reader)
        assert reply == Socks5ConnectionReply.SUCCEEDED
        assert ip == ipaddress.IPv6Address('::1')
        writer.write(b'ping')
        assert await asyncio.wait_for(reader.readexactly(4), timeout=1) == b'ping'
        await close_writer(writer)


@pytest.mark.asyncio
async def test_socks5h_unresolvable_domain() -> None:
    protocol = soxy.Socks5(resolver=soxy.SystemResolver(timeout=2))
    async with run_proxy(protocol=protocol) as proxy_port:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
        writer.write(GREETING + socks5_domain_request('does-not-exist.invalid', 80))
        assert await reader.readexactly(2) == b'\x05\x00'
        reply, _, _ = await asyncio.wait_for(read_socks5_reply(reader), timeout=5)
        assert reply == Socks5ConnectionReply.HOST_UNREACHABLE
        await close_writer(writer)
