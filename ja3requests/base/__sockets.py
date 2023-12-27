from abc import ABC, abstractmethod


class BaseSocket(ABC):

    @abstractmethod
    def new_conn(self):

        raise NotImplementedError("new_conn method must be implemented by subclass.")
