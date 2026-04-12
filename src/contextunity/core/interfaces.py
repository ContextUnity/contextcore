from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from .sdk import ContextUnit


class BaseTransformer(ABC):
    """Logic pipes: pure-ish transformation over ContextUnit."""

    def __init__(self):
        self._params: Dict[str, Any] = {}

    def configure(self, params: Optional[Dict[str, Any]] = None):
        self._params = dict(params or {})

    @property
    def params(self) -> Dict[str, Any]:
        return self._params

    @abstractmethod
    async def transform(self, unit: ContextUnit) -> ContextUnit:
        raise NotImplementedError


class Transformer(BaseTransformer):
    """Convenience base class for transformers."""

    name: str = "transformer"

    async def transform(self, unit: ContextUnit) -> ContextUnit:
        # Trace implementation via sdk.py
        unit.provenance.append(self.name)
        return await self._transform(unit)

    @abstractmethod
    async def _transform(self, unit: ContextUnit) -> ContextUnit:
        pass


__all__ = ["BaseTransformer", "Transformer"]
