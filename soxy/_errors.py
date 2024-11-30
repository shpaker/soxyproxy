from ipaddress import IPv4Address, IPv6Address


class PackageError(
    ValueError,
):
    def __init__(
        self,
        data: bytes,
        *args,
        **kwargs,
    ) -> None:
        self._data = data
        super().__init__(*args, **kwargs)

    @property
    def data(self) -> bytes:
        return self._data


class ProtocolError(
    Exception,
):
    pass


class ResolveDomainError(
    ProtocolError,
):
    def __init__(
        self,
        domain: str,
    ) -> None:
        self._domain = domain

    @property
    def domain(self):
        return self._domain


class AuthorizationError(
    ProtocolError,
):
    def __init__(
        self,
        username: str,
    ) -> None:
        self._username = username

    @property
    def username(self):
        return self._username


class RejectError(
    ProtocolError,
):
    def __init__(
        self,
        address: str | IPv4Address | IPv6Address,
        port: int,
    ) -> None:
        self._address = address
        self._port = port

    @property
    def address(
        self,
    ) -> str | IPv4Address | IPv6Address:
        return self._address

    @property
    def port(
        self,
    ) -> int:
        return self._port
