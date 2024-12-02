from soxy._types import Address


class PackageError(
    ValueError,
):
    def __init__(
        self,
        data: bytes,
    ) -> None:
        self._data = data
        super().__init__()

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
        domain_name: str,
        port: int,
    ) -> None:
        self._domain = domain_name
        self._port = port

    @property
    def domain(
        self,
    ) -> str:
        return self._domain

    @property
    def port(
        self,
    ) -> int:
        return self._port


class AuthorizationError(
    ProtocolError,
):
    def __init__(
        self,
        username: str,
    ) -> None:
        self._username = username

    @property
    def username(
        self,
    ) -> str:
        return self._username


class RejectError(
    ProtocolError,
):
    def __init__(
        self,
        address: Address,
    ) -> None:
        self._address = address

    @property
    def address(
        self,
    ) -> Address:
        return self._address
