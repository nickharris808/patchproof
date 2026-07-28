"""patchproof — prove a bounds-check fix eliminates every violating input, not just the one you saw.

The verification half of this package (`patchproof.linear`) is deliberately
solver-free: replaying an elimination certificate is integer arithmetic, so a
sceptic can check our work without installing or trusting z3.  The proving half
needs z3, and is therefore imported lazily — `import patchproof.linear` must not
drag a solver in, and a test enforces that.
"""

from .linear import Certificate, LinearForm, ReplayError, find_certificate, replay, verify

__version__ = "0.1.0"

_LAZY = {
    "CLASSES": "model", "OUT_OF_MODEL": "model", "REAL_CLASSES": "model",
    "DefectClass": "model", "Field": "model",
    "Result": "prover", "Witness": "prover", "find_exploit": "prover",
    "prove": "prover",
}


def __getattr__(name):
    """Import the solver-backed half only when it is actually asked for."""
    mod = _LAZY.get(name)
    if mod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f".{mod}", __name__), name)


def __dir__():
    return sorted(list(globals()) + list(_LAZY))


__all__ = [
    "CLASSES",
    "OUT_OF_MODEL",
    "REAL_CLASSES",
    "Certificate",
    "DefectClass",
    "Field",
    "LinearForm",
    "ReplayError",
    "Result",
    "Witness",
    "__version__",
    "find_certificate",
    "find_exploit",
    "prove",
    "replay",
    "verify",
]
