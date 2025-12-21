import argparse
import asyncio
import logging
import sys
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


def _run_proxy(config_path: Path, logfile: str | None) -> None:
    validate_config_path(config_path)
    config = load_config(config_path)
    asyncio.run(async_main(config, logfile))


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Start soxyproxy server with the given configuration file.',
    )
    parser.add_argument(
        'config',
        type=Path,
        help='Path to configuration file',
    )
    parser.add_argument(
        '--logfile',
        '-l',
        type=Path,
        default=None,
        help='Path to log file. If not specified, logs will be printed to terminal.',
    )

    args = parser.parse_args()
    logfile_str = str(args.logfile) if args.logfile else None
    _run_proxy(args.config, logfile_str)


if __name__ == '__main__':
    main()
