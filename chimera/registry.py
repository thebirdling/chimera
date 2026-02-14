"""
Detector registry for Chimera.

Provides a central registry mapping detector names to their classes,
enabling plug-and-play model selection via CLI or config files.
"""

from __future__ import annotations

from typing import Optional, Type
import logging

from chimera.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """
    Singleton registry that maps detector names to their implementing classes.

    Usage::

        # Register a new detector
        @DetectorRegistry.register
        class MyDetector(BaseDetector):
            name = "my_detector"
            ...

        # Look up by name
        cls = DetectorRegistry.get("my_detector")
        detector = cls()

        # List all available detectors
        for name, cls in DetectorRegistry.list_detectors():
            print(f"{name}: {cls.description}")
    """

    _registry: dict[str, Type[BaseDetector]] = {}

    @classmethod
    def register(cls, detector_cls: Type[BaseDetector]) -> Type[BaseDetector]:
        """
        Register a detector class. Can be used as a decorator.

        Args:
            detector_cls: A BaseDetector subclass with a unique ``name`` attribute.

        Returns:
            The same class, unmodified (decorator-friendly).
        """
        name = getattr(detector_cls, "name", None)
        if not name:
            raise ValueError(
                f"Detector class {detector_cls.__name__} must define a 'name' attribute."
            )

        if name in cls._registry:
            logger.warning(
                f"Overwriting existing detector '{name}' "
                f"({cls._registry[name].__name__} → {detector_cls.__name__})"
            )

        cls._registry[name] = detector_cls
        logger.debug(f"Registered detector: {name} → {detector_cls.__name__}")
        return detector_cls

    @classmethod
    def get(
        cls, name: str, default: Optional[Type[BaseDetector]] = None
    ) -> Type[BaseDetector]:
        """
        Retrieve a detector class by name.

        Args:
            name: Registered detector name.
            default: Fallback class if name is not found.

        Returns:
            The detector class.

        Raises:
            KeyError: If name is not registered and no default is given.
        """
        if name in cls._registry:
            return cls._registry[name]
        if default is not None:
            return default
        available = ", ".join(sorted(cls._registry.keys())) or "(none)"
        raise KeyError(
            f"Unknown detector '{name}'. Available detectors: {available}"
        )

    @classmethod
    def list_detectors(cls) -> list[tuple[str, Type[BaseDetector]]]:
        """Return a sorted list of (name, class) pairs."""
        return sorted(cls._registry.items())

    @classmethod
    def names(cls) -> list[str]:
        """Return sorted list of registered detector names."""
        return sorted(cls._registry.keys())

    @classmethod
    def clear(cls) -> None:
        """Clear all registrations (useful for testing)."""
        cls._registry.clear()

    @classmethod
    def create(cls, name: str, **kwargs) -> BaseDetector:
        """
        Convenience factory: look up by name and instantiate.

        Args:
            name: Registered detector name.
            **kwargs: Passed to the detector's ``__init__``.

        Returns:
            An instance of the requested detector.
        """
        detector_cls = cls.get(name)
        return detector_cls(**kwargs)
