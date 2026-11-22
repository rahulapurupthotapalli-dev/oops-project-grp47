"""REPOSITORY pattern: the service layer depends on this interface, not on storage.
Step 3 will add SQLiteRepository without changing any business code."""
from abc import ABC, abstractmethod

from .exceptions import EntityNotFound


class Repository(ABC):
    @abstractmethod
    def save(self, entity): ...
    @abstractmethod
    def get(self, entity_id): ...
    @abstractmethod
    def all(self) -> list: ...


class InMemoryRepository(Repository):
    def __init__(self, not_found=EntityNotFound):
        self._items, self._not_found = {}, not_found

    def save(self, entity): self._items[entity.id] = entity

    def get(self, entity_id):
        try:
            return self._items[entity_id]
        except KeyError:
            raise self._not_found(f"{entity_id} not found") from None

    def all(self): return list(self._items.values())
