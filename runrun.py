import asyncio

import httpx
from httpx_socks import AsyncProxyTransport


async def main() -> None:
    transport = AsyncProxyTransport.from_url('socks5://127.0.0.1:1080', rdns=False)
    async with httpx.AsyncClient(transport=transport) as client:
        await client.get('https://ya.ru')


if __name__ == '__main__':
    asyncio.run(main())
