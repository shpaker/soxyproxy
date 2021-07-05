from abc import ABC, abstractmethod


class RequestMessage(ABC):
    @staticmethod
    @abstractmethod
    def from_bytes(raw: bytes):
        raise NotImplementedError


class ResponseMessage(ABC):
    @property
    @abstractmethod
    def as_bytes(self):
        raise NotImplementedError
