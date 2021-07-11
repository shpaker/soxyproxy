from logging import basicConfig, getLogger

from httpx import AsyncClient, Response
from httpx_socks import ProxyError
from pytest import mark

from soxyproxy.consts import Socks4Reply

logger = getLogger(__name__)
basicConfig(level="DEBUG")


@mark.asyncio
async def test_correct_request(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks4")
    async with AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()


@mark.asyncio
async def test_incorrect_request(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    proxy_transport,
) -> None:
    transport = proxy_transport("socks4")
    async with AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://127.0.0.1:9449/get")
            res.raise_for_status()
        except ProxyError as err:
            assert err.error_code == Socks4Reply.REJECTED, err


@mark.asyncio
async def test_correct_package(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    send_data,
) -> None:
    msg = b"\x04\x01\x01\xbb\x12\xeb|\xd6\x00"
    data = await send_data(msg)
    assert data[0] == 0, data
    assert data[1] == Socks4Reply.GRANTED, data


@mark.asyncio
async def test_incorrect_protocol(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    send_data,
) -> None:
    broken_msg = b"\x05\x01\x01\xbb\x12\xeb|\xd6\x00"
    data = await send_data(broken_msg)
    assert not data, data


@mark.asyncio
async def test_short_package(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    send_data,
) -> None:
    broken_msg = b"\x05\x01\x01"
    data = await send_data(broken_msg)
    assert not data, data


@mark.asyncio
async def test_not_null_terminated(
    run_socks4_server,  # noqa, pylint: disable=unused-argument
    send_data,
) -> None:
    broken_msg = b"\x04\x01\x01\xbb\x12\xeb|\xd6\x01"
    data = await send_data(broken_msg)
    assert not data, data
