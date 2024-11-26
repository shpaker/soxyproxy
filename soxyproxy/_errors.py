from soxyproxy._types import Destination


class SocksPackageError(ValueError):
    def __init__(self, data: bytes, *args, **kwargs) -> None:
        self._data = data
        super().__init__(*args, **kwargs)

    @property
    def data(self) -> bytes:
        return self._data


class SocksIncorrectVersionError(SocksPackageError):
    pass


class SocksError(Exception):
    pass


class SocksRejectError(SocksError):
    def __init__(
        self,
        destination: Destination,
    ) -> None:
        self._destination = destination

    @property
    def destination(self):
        return self._destination
