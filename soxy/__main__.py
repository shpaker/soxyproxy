import asyncio
import logging
from pathlib import Path

from soxy import Config, Proxy


async def async_main() -> None:
    config = Config.from_path(Path('config.toml'))
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(async_main())
