import asyncio
import logging
from pathlib import Path

from soxy import Config, Proxy


async def amain(
    config: Config,
) -> None:
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(
        amain(
            config=Config.from_path(Path("config.toml")),
        )
    )
