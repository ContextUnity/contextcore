"""Core pipeline interfaces — shared ABCs for connectors and transformers.

``BaseConnector`` and ``BaseTransformer`` are service-agnostic primitives
used identically by Router and Brain.  They live in core so that both
services import from a single canonical definition.

Service-specific interfaces (``BaseAgent``, ``IRead``, ``IWrite``,
``BaseProvider``) remain in their owning services because their contracts
diverge (e.g. Brain requires ``ContextToken``; Router does not).

Transformer configuration:
    - ``JsonConfigurableTransformer`` — ``configure()`` validates L2 ``JsonDict`` at runtime.
    - ``BaseTransformer`` — open ``dict[str, object]`` bag; service subclasses may
      override ``configure()`` to accept domain objects (see router ``GraphTransformer``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, override

from contextunity.core.exceptions import ConfigurationError
from contextunity.core.types import is_json_dict

if TYPE_CHECKING:
    from contextunity.core import ContextUnit


class BaseConnector(ABC):
    """Sources: produce raw data wrapped in ContextUnit envelope.

    Implementations yield ContextUnits asynchronously.  The caller is
    responsible for error handling and backpressure.
    """

    @abstractmethod
    def connect(self) -> AsyncIterator[ContextUnit]:
        """Yield ContextUnits from the external data source.

        Yields:
            ContextUnit from the data source.
        """
        raise NotImplementedError


class BaseTransformer(ABC):
    """Logic pipes: pure-ish transformation over ContextUnit envelope.

    Supports optional configuration via ``configure()`` before transformation.
    The internal store is an open bag (``dict[str, object]``). JSON-only
    transformers should subclass ``JsonConfigurableTransformer``.
    """

    def __init__(self) -> None:
        """Initialize with empty configuration dict."""
        self._params: dict[str, object] = {}

    def configure(self, params: dict[str, object] | None) -> None:
        """Apply configuration parameters before transformation.

        Args:
            params: Key-value configuration dict, or ``None`` to reset.
                Values may include service-specific objects when a subclass
                overrides this method in the owning service package.
        """
        self._params = dict(params or {})

    @property
    def params(self) -> dict[str, object]:
        """Return a defensive copy of the current configuration.

        Returns:
            Shallow copy of the internal params dict.
        """
        return dict(self._params)

    @abstractmethod
    async def transform(self, unit: ContextUnit) -> ContextUnit:
        """Apply domain-specific transformation to a ContextUnit.

        Args:
            unit: Input ContextUnit to transform.

        Returns:
            Transformed ContextUnit (may be the same instance, mutated).
        """
        raise NotImplementedError


class JsonConfigurableTransformer(BaseTransformer, ABC):
    """Transformer whose ``configure()`` params must be a JSON object (L2).

    Use for manifest/flow YAML params validated via Pydantic in the service
    layer. Do not use when params carry live domain models — subclass
    ``BaseTransformer`` in the service instead.
    """

    @override
    def configure(self, params: dict[str, object] | None) -> None:
        if params is None:
            super().configure(None)
            return
        if not is_json_dict(params):
            raise ConfigurationError("Transformer configure params must be a JSON object mapping")
        super().configure(dict(params))


__all__ = [
    "BaseConnector",
    "BaseTransformer",
    "JsonConfigurableTransformer",
]
