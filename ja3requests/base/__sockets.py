from abc import ABC, abstractmethod


class BaseSocket(ABC):

    def __init__(self, context):
        self.context = context

    @abstractmethod
    def new_conn(self):

        raise NotImplementedError("new_conn method must be implemented by subclass.")
