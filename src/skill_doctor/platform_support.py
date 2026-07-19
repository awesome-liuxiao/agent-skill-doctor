from __future__ import annotations

from types import ModuleType
from typing import Any


def module_attribute(module: ModuleType, name: str) -> Any:
    """Read an OS-specific module member without fixing it in another OS's stub."""
    return getattr(module, name)


def module_int(module: ModuleType, name: str) -> int:
    return int(module_attribute(module, name))
