import logging
from logging import getLogger, basicConfig
from typing import Dict

import httpx
import requests
from httpx import Response
from httpx_socks import AsyncProxyTransport, ProxyError
from pytest import mark
from asyncio import open_connection

from soxyproxy.consts import Socks4Reply

logger = getLogger(__name__)
basicConfig(level="DEBUG")


async def send_data(data: bytes):
    reader, writer = await open_connection('127.0.0.1', 8888)
    writer.write(data)
    await writer.drain()
    data = await reader.read(100)
    writer.close()
    await writer.wait_closed()
    return data


@mark.asyncio
async def test_correct_request(
    run_server,
) -> None:
    transport = AsyncProxyTransport.from_url('socks4://127.0.0.1:8888')
    async with httpx.AsyncClient(transport=transport) as client:
        res: Response = await client.get("https://httpbin.org/get")
        res.raise_for_status()


@mark.asyncio
async def test_incorrect_request(
    run_server,
) -> None:
    transport = AsyncProxyTransport.from_url('socks4://127.0.0.1:8888')
    async with httpx.AsyncClient(transport=transport) as client:
        try:
            res: Response = await client.get("https://127.0.0.1:9449/get")
            res.raise_for_status()
        except ProxyError as err:
            assert err.error_code == Socks4Reply.REJECTED, err


@mark.asyncio
async def test_correct_package(
    run_server,
) -> None:
    msg = b"\x04\x01\x01\xbb\x12\xeb|\xd6\x00"
    data = await send_data(msg)
    assert data[0] == 0, data
    assert data[1] == Socks4Reply.GRANTED, data


@mark.asyncio
async def test_incorrect_protocol(
    run_server,
) -> None:
    broken_msg = b"\x05\x01\x01\xbb\x12\xeb|\xd6\x00"
    data = await send_data(broken_msg)
    assert not data, data


@mark.asyncio
async def test_short_package(
    run_server,
) -> None:
    broken_msg = b"\x05\x01\x01"
    data = await send_data(broken_msg)
    assert not data, data


@mark.asyncio
async def test_not_null_terminated(
    run_server,
) -> None:
    broken_msg = b"\x04\x01\x01\xbb\x12\xeb|\xd6\x01"
    data = await send_data(broken_msg)
    assert not data, data
