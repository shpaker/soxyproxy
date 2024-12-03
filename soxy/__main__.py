import asyncio
import logging
import sys
from contextlib import suppress
from pathlib import Path
from tomllib import TOMLDecodeError

from soxy import Config, ConfigError, Proxy, logger


async def async_main() -> None:
    try:
        config_filename = sys.argv[1]
    except IndexError:
        logger.error('🥹: please, give me my config')
        sys.exit(1)
    if not (config_path := Path(config_filename)).exists():
        logger.error("🥹: config file doesn't exists")
        sys.exit(1)
    try:
        config = Config.from_path(config_path)
    except (ConfigError, TOMLDecodeError) as exc:
        logger.error(f'🥹: {exc}')
        sys.exit(1)
    logfile: str | None = None
    with suppress(IndexError):
        logfile = sys.argv[2]
    logging.basicConfig(
        level=logging.INFO,
        filename=logfile,
    )
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


def main() -> None:
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
