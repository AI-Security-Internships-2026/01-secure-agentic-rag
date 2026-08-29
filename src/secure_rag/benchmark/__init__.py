"""AuthInject-RAG benchmark.

Submodules are imported lazily so that `python -m secure_rag.benchmark.runner`
does not load the module twice via this package.
"""

from typing import Any

__all__ = ["main", "run_matrix"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from secure_rag.benchmark import runner

        return getattr(runner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
