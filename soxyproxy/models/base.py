from abc import ABC, abstractmethod

from pydantic import BaseModel


class RequestBaseModel(ABC, BaseModel):
    @classmethod
    @abstractmethod
    def loads(
        cls,
        raw: bytes,
    ) -> "RequestBaseModel":
        raise NotImplementedError


class ResponseBaseModel(ABC, BaseModel):
    @abstractmethod
    def dumps(self) -> bytes:
        raise NotImplementedError
