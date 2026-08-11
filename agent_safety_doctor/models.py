from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high": 18,
    "medium": 9,
    "low": 4,
    "info": 0,
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: str
    path: str
    detail: str
    fix: str
    line: int | None = None
    evidence: str | None = None
    rule_id: str | None = None

    @property
    def stable_id(self) -> str:
        suffix = f":{self.line}" if self.line else ""
        return f"{self.category}:{self.path}{suffix}"

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["id"] = self.stable_id
        return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True)
class ScanMetadata:
    root: str
    started_at: str
    completed_at: str
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    config_path: str | None = None

    @classmethod
    def start(cls, root: Path, config_path: Path | None = None) -> "ScanMetadataBuilder":
        return ScanMetadataBuilder(root=root, config_path=config_path, started_at=datetime.now(timezone.utc))


@dataclass
class ScanMetadataBuilder:
    root: Path
    config_path: Path | None
    started_at: datetime
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0

    def finish(self) -> ScanMetadata:
        return ScanMetadata(
            root=str(self.root),
            started_at=self.started_at.isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            files_scanned=self.files_scanned,
            files_skipped=self.files_skipped,
            bytes_scanned=self.bytes_scanned,
            config_path=str(self.config_path) if self.config_path else None,
        )


@dataclass(frozen=True)
class ScanResult:
    metadata: ScanMetadata
    findings: list[Finding]

    @property
    def score(self) -> int:
        score = 100
        for finding in self.findings:
            score -= SEVERITY_WEIGHTS.get(finding.severity, 0)
        return max(0, score)

    @property
    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_WEIGHTS}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["total"] = len(self.findings)
        return counts

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "metadata": asdict(self.metadata),
            "score": self.score,
            "counts": self.counts,
            "findings": [finding.as_dict() for finding in self.findings],
        }
