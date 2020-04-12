from abc import ABC, abstractmethod


class ProtocolResponse(ABC):

    @property
    @abstractmethod
    def as_bytes(self):
        raise NotImplementedError
