from abc import ABC, abstractmethod
from ja3requests.base.__contexts import BaseContext


class BaseSocket(ABC):

    def __init__(self, context: BaseContext):
        self.context = context
        self._conn = None

    @property
    def conn(self):

        return self._conn

    @conn.setter
    def conn(self, attr):

        self._conn = attr

    @abstractmethod
    def new_conn(self):

        raise NotImplementedError("new_conn method must be implemented by subclass.")
