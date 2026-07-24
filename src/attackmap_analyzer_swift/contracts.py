"""Re-exports of the AttackMap analyzer SDK surface this plugin depends on.

Everything here comes from the stable ``attackmap.sdk`` contract (requires
attackmap >= 0.4.29, which exports ``DependencyHint``). Kept in one place so a
future SDK move is a one-file change.
"""

from __future__ import annotations

from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
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
