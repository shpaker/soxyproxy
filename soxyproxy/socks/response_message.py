from abc import ABC, abstractmethod


class ResponseMessage(ABC):

    @property
    @abstractmethod
    def as_bytes(self):
        raise NotImplementedError
