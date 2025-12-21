import pytest

from soxy._types import Address, Connection


def pytest_configure(
    config: pytest.Config,
) -> None:
    config.addinivalue_line('markers', 'socks_obj(obj): ')
    config.addinivalue_line('markers', 'socks: marks tests as socks integration tests (deselect with -m "not socks")')


@pytest.fixture
def connection() -> Connection:
    return Connection(address='192.168.1.1')


@pytest.fixture
def address() -> Address:
    return Address(ip='192.168.1.2', port=80)
