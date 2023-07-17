from abc import ABC, abstractmethod


class BaseRequest(ABC):

    @abstractmethod
    def send(self):

        raise NotImplementedError("send method must be implemented by subclass.")