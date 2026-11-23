# plugins/base.py

from abc import ABC, abstractmethod

class TestPlugin(ABC):

    name = "Unnamed"

    @abstractmethod
    def execute(self, device, logger, use_hardware=False):
        pass