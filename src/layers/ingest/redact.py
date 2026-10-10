"""
layers – ingest/redact.py
Standalone redaction helpers used at ingest time.
Re-exports the safety module's functions so the rest of the codebase
imports from one place.
"""

from layers.safety import (
    redact_all,
    redact_body,
    redact_headers,
    redact_url,
)

__all__ = ["redact_url", "redact_headers", "redact_body", "redact_all"]
