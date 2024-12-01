from pathlib import Path
import asyncio

from soxyproxy import Proxy, Config
import logging

logging.basicConfig(level=logging.INFO)


async def amain(
    config: Config,
) -> None:
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


if __name__ == "__main__":
    asyncio.run(
        amain(
            config=Config.from_path(Path("config.toml")),
        )
    )
