import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soxy import Config
from soxy.__main__ import (
    _run_proxy,
    async_main,
    load_config,
    main,
    validate_config_path,
)


@pytest.fixture
def temp_config_file(tmp_path: Path) -> Path:
    config_content = """
[proxy]
protocol = "socks5"
transport = "tcp"

[transport]
host = "127.0.0.1"
port = 1080

[[ruleset.connecting.allow]]
from = "127.0.0.1"

[[ruleset.proxying.allow]]
from = "127.0.0.1"
to = "0.0.0.0/0"
"""
    config_file = tmp_path / 'test_config.toml'
    config_file.write_text(config_content)
    return config_file


def test_validate_config_path_exists(temp_config_file: Path) -> None:
    # Should not raise
    validate_config_path(temp_config_file)


def test_validate_config_path_not_exists(tmp_path: Path) -> None:
    non_existent = tmp_path / 'nonexistent.toml'
    with pytest.raises(SystemExit):
        validate_config_path(non_existent)


def test_load_config_valid(temp_config_file: Path) -> None:
    config = load_config(temp_config_file)
    assert isinstance(config, Config)
    assert config.socks is not None
    assert config.transport is not None


def test_load_config_invalid_path(tmp_path: Path) -> None:
    non_existent = tmp_path / 'nonexistent.toml'
    with pytest.raises(SystemExit):
        load_config(non_existent)


def test_load_config_invalid_toml(tmp_path: Path) -> None:
    invalid_file = tmp_path / 'invalid.toml'
    invalid_file.write_text('invalid toml content!!!')
    with pytest.raises(SystemExit):
        load_config(invalid_file)


@pytest.mark.asyncio
async def test_async_main(temp_config_file: Path) -> None:
    config = Config.from_path(temp_config_file)

    # Mock Proxy to avoid actually starting server
    with patch('soxy.__main__.Proxy') as mock_proxy_class:
        mock_app = AsyncMock()
        mock_app.serve_forever = AsyncMock()

        mock_proxy = AsyncMock()
        mock_proxy.__aenter__ = AsyncMock(return_value=mock_app)
        mock_proxy.__aexit__ = AsyncMock(return_value=None)
        mock_proxy_class.from_config.return_value = mock_proxy

        # Create a task that will be cancelled
        task = asyncio.create_task(async_main(config, None))
        await asyncio.sleep(0.01)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_async_main_with_logfile(temp_config_file: Path, tmp_path: Path) -> None:
    config = Config.from_path(temp_config_file)
    logfile = str(tmp_path / 'test.log')

    with patch('soxy.__main__.Proxy') as mock_proxy_class:
        mock_app = AsyncMock()
        mock_app.serve_forever = AsyncMock()

        mock_proxy = AsyncMock()
        mock_proxy.__aenter__ = AsyncMock(return_value=mock_app)
        mock_proxy.__aexit__ = AsyncMock(return_value=None)
        mock_proxy_class.from_config.return_value = mock_proxy

        task = asyncio.create_task(async_main(config, logfile))
        await asyncio.sleep(0.01)
        task.cancel()

        try:
            await task
        except asyncio.CancelledError:
            pass


def test_run_proxy(temp_config_file: Path) -> None:
    with patch('soxy.__main__.asyncio.run') as mock_run:
        _run_proxy(temp_config_file, None)
        mock_run.assert_called_once()


def test_run_proxy_with_logfile(temp_config_file: Path) -> None:
    with patch('soxy.__main__.asyncio.run') as mock_run:
        _run_proxy(temp_config_file, 'test.log')
        mock_run.assert_called_once()


def test_main_with_valid_args(temp_config_file: Path) -> None:
    """Test that main function works with valid arguments"""
    with patch('soxy.__main__._run_proxy') as mock_run_proxy:
        with patch.object(sys, 'argv', ['soxy', str(temp_config_file)]):
            main()
            mock_run_proxy.assert_called_once_with(temp_config_file, None)


def test_main_with_logfile(temp_config_file: Path, tmp_path: Path) -> None:
    """Test that main function works with logfile argument"""
    logfile = tmp_path / 'test.log'
    with patch('soxy.__main__._run_proxy') as mock_run_proxy:
        with patch.object(sys, 'argv', ['soxy', str(temp_config_file), '--logfile', str(logfile)]):
            main()
            mock_run_proxy.assert_called_once_with(temp_config_file, str(logfile))


def test_main_with_short_logfile_option(temp_config_file: Path, tmp_path: Path) -> None:
    """Test that main function works with short logfile option"""
    logfile = tmp_path / 'test.log'
    with patch('soxy.__main__._run_proxy') as mock_run_proxy:
        with patch.object(sys, 'argv', ['soxy', str(temp_config_file), '-l', str(logfile)]):
            main()
            mock_run_proxy.assert_called_once_with(temp_config_file, str(logfile))


def test_main_missing_config() -> None:
    """Test that main function handles missing config argument"""
    with patch.object(sys, 'argv', ['soxy']):
        with pytest.raises(SystemExit) as exc_info:
            main()
        # argparse will exit with code 2 for missing required argument
        assert exc_info.value.code == 2


def test_main_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test that main function shows help"""
    with patch.object(sys, 'argv', ['soxy', '--help']):
        with pytest.raises(SystemExit) as exc_info:
            main()
        # argparse will exit with code 0 for --help
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert 'Start soxyproxy server' in captured.out
        assert '--logfile' in captured.out

