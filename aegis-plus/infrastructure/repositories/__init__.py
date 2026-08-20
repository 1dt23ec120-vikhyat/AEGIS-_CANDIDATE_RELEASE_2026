"""Repository implementations.

Concrete implementations of the Core :class:`~core.interfaces.IRepository` port,
plus the entity-type to repository-factory registry used by the Unit of Work.
"""

from infrastructure.repositories.base_repository import SqlAlchemyRepository
from infrastructure.repositories.registry import (
    RepositoryFactory,
    default_repository_factories,
)

__all__ = [
    "RepositoryFactory",
    "SqlAlchemyRepository",
    "default_repository_factories",
]
