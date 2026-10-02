from __future__ import annotations

from attackmap.sdk.contracts import AnalyzerMetadata, AnalyzerProtocol
from attackmap.sdk.models import (
    AuthHint,
    DatabaseHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

# Compatibility alias used by existing analyzer implementations.
AttackMapAnalyzerProtocol = AnalyzerProtocol

__all__ = [
    "AnalyzerMetadata",
    "AttackMapAnalyzerProtocol",
    "Route",
    "ExternalCall",
    "DatabaseHint",
    "AuthHint",
    "ServiceHint",
    "EdgeHint",
    "EntrypointHint",
    "ProtocolHint",
    "SecretHint",
    "ScanResult",
]
