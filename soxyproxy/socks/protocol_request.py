from abc import ABC, abstractmethod


class ProtocolRequest(ABC):

    @staticmethod
    @abstractmethod
    def from_bytes(raw: bytes):
        raise NotImplementedError
