import asyncio
import logging
import sys
from contextlib import suppress
from pathlib import Path
from tomllib import TOMLDecodeError

from soxy import Config, ConfigError, Proxy, logger


def validate_config_path(config_path: Path) -> None:
    if not config_path.exists():
        logger.error("🥹: config file doesn't exist")
        sys.exit(1)


def load_config(config_path: Path) -> Config:
    try:
        return Config.from_path(config_path)
    except (ConfigError, TOMLDecodeError) as exc:
        logger.error(f'🥹: {exc}')
        sys.exit(1)


async def async_main(config: Config, logfile: str | None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        filename=logfile,
    )
    async with Proxy.from_config(config) as app:
        await app.serve_forever()


def main() -> None:
    try:
        config_filename = sys.argv[1]
    except IndexError:
        logger.error('🥹: please, give me my config')
        sys.exit(1)

    config_path = Path(config_filename)
    validate_config_path(config_path)

    config = load_config(config_path)

    logfile: str | None = None
    with suppress(IndexError):
        logfile = sys.argv[2]

    asyncio.run(async_main(config, logfile))


if __name__ == '__main__':
    main()
