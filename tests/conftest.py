from ipaddress import IPv4Address

import pytest

from soxy import (
    Connection,
    Resolver,
)


class _FakeConn(Connection): ...


@pytest.fixture
def resolver() -> Resolver:
    def _resolver(
        name: str,
    ) -> IPv4Address:
        if name == "google.com":
            return IPv4Address("1.1.1.1")

    return _resolver
