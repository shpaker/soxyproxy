from abc import ABC, abstractmethod

from pydantic import BaseModel

from soxyproxy.models.client import ClientModel


class RequestBaseModel(ABC, BaseModel):
    @classmethod
    @abstractmethod
    def loads(
        cls,
        client: ClientModel,
        raw: bytes,
    ) -> "RequestBaseModel":
        raise NotImplementedError


class ResponseBaseModel(ABC, BaseModel):
    @abstractmethod
    def dumps(self) -> bytes:
        raise NotImplementedError
