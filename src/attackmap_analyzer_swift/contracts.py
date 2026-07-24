"""Re-exports of the AttackMap analyzer SDK surface this plugin depends on.

Kept in one place so a future SDK move is a one-file change. ``DependencyHint``
is not part of the trimmed ``attackmap.sdk.models`` surface, so it is imported
from the core models module — analyzers already require ``attackmap`` at runtime.
"""

from __future__ import annotations

from attackmap.models import DependencyHint
from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

AttackMapAnalyzerProtocol = AnalyzerProtocol

__all__ = [
    "AnalyzerMetadata",
    "AttackMapAnalyzerProtocol",
    "AuthHint",
    "DatabaseHint",
    "DependencyHint",
    "EntrypointHint",
    "ExternalCall",
    "FrameworkHint",
    "Route",
    "ScanResult",
    "SecretHint",
    "ServiceHint",
]
