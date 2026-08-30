"""Compatibility entry point for the Week 8 guardrail comparison command.

The original script compared prompt patterns while labelling them as complete
frameworks.  The maintained benchmark now runs technically equivalent local
retrieved-context classifiers and records unsupported components honestly.
"""

from __future__ import annotations

from secure_rag.benchmark.guardrail_compare import main

if __name__ == "__main__":
    main()
