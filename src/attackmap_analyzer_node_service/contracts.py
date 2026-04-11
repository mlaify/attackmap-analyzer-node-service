from __future__ import annotations

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

try:
    from attackmap.models import AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint  # type: ignore
except ImportError:
    class Route(BaseModel):
        path: str
        method: str = "ANY"
        file: str

    class ExternalCall(BaseModel):
        target: str
        file: str

    class DatabaseHint(BaseModel):
        kind: str
        file: str

    class AuthHint(BaseModel):
        hint: str
        file: str

    class SecretHint(BaseModel):
        name: str
        file: str

    class ScanResult(BaseModel):
        root: str
        languages: list[str] = Field(default_factory=list)
        routes: list[Route] = Field(default_factory=list)
        external_calls: list[ExternalCall] = Field(default_factory=list)
        databases: list[DatabaseHint] = Field(default_factory=list)
        auth_hints: list[AuthHint] = Field(default_factory=list)
        secret_hints: list[SecretHint] = Field(default_factory=list)
        files_scanned: int = 0


class AttackMapAnalyzerProtocol(Protocol):
    metadata: "AnalyzerMetadata"

    @property
    def name(self) -> str: ...

    def detect(self, repo_path: str | Path) -> bool: ...

    def analyze(self, repo_path: str | Path) -> ScanResult: ...


class AnalyzerMetadata(BaseModel):
    name: str
    display_name: str
    version: str
    description: str
    scope: str
    targets: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    priority: int = 100
    experimental: bool = True
    enabled_by_default: bool = False

    @property
    def ecosystems(self) -> tuple[str, ...]:
        values = [*self.languages, *self.targets]
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            lower_value = value.lower()
            if lower_value in seen:
                continue
            seen.add(lower_value)
            ordered.append(lower_value)
        return tuple(ordered)
