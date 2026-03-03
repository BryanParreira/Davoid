# core/plugin.py
from abc import ABC, abstractmethod
from rich.console import Console

console = Console()


class DavoidPlugin(ABC):
    """
    Base class for the Davoid Scripting Engine (DSE).
    Any Python script placed in the /plugins directory that inherits from this
    will automatically be loaded into the Davoid Master Console.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """The display name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """A short description of what the plugin does."""
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """The creator of the plugin."""
        pass

    @abstractmethod
    def run(self) -> None:
        """The main execution logic of the plugin."""
        pass
