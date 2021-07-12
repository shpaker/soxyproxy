from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

from soxyproxy.connections import SocksConnection
from soxyproxy.exceptions import SocksPackageError

TRequestBase = TypeVar("TRequestBase", bound="RequestBaseModel")  # type: ignore


class RequestBaseModel(
    ABC,
    BaseModel,
    Generic[TRequestBase],
):
    @classmethod
    @abstractmethod
    def loader(
        cls,
        raw: bytes,
    ) -> TRequestBase:
        raise NotImplementedError

    @classmethod
    def load(
        cls,
        client: SocksConnection,
        raw: bytes,
    ) -> TRequestBase:
        try:
            return cls.loader(raw)
        except (IndexError, ValueError) as err:
            raise SocksPackageError(client=client, raw=raw) from err


class ResponseBaseModel(ABC, BaseModel):
    @abstractmethod
    def dump(self) -> bytes:
        raise NotImplementedError
