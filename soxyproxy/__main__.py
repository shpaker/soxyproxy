import asyncio
import logging
from pathlib import Path

from soxyproxy import Config, Proxy

logging.basicConfig(level=logging.INFO)


async def amain(
    config: Config,
) -> None:
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


if __name__ == '__main__':
    asyncio.run(
        amain(
            config=Config.from_path(Path('config.toml')),
        )
    )
