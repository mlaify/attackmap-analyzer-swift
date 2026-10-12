"""Re-exports of the AttackMap analyzer SDK surface this plugin depends on.

Everything here comes from the stable ``attackmap.sdk`` contract (requires an
attackmap that exports ``AppSurfaceIssue`` and the ``carthage`` ecosystem,
mlaify/AttackMap#347). Kept in one place so a
future SDK move is a one-file change.
"""

from __future__ import annotations

from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
    AppSurfaceIssue,
    AuthHint,
    DatabaseHint,
    DependencyHint,
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
    "AppSurfaceIssue",
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
