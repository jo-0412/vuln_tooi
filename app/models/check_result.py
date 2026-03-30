from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


VALID_STATUSES = {"PASS", "FAIL", "MANUAL", "ERROR"}


@dataclass
class EvidenceItem:
    key: str
    label: str
    source: str
    value: Any
    status: str = "info"
    excerpt: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    code: str
    name: str
    severity: str
    category: str
    status: str
    success: bool
    summary: str
    detail: str
    requires_root: str = "unknown"
    remediation_summary: Optional[str] = None
    remediation_steps: list[str] = field(default_factory=list)
    evidences: list[EvidenceItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        self.status = self.status.upper()
        if self.status not in VALID_STATUSES:
            raise ValueError(f"지원하지 않는 상태값입니다: {self.status}")

    def add_evidence(
        self,
        *,
        key: str,
        label: str,
        source: str,
        value: Any,
        status: str = "info",
        excerpt: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        self.evidences.append(
            EvidenceItem(
                key=key,
                label=label,
                source=source,
                value=value,
                status=status,
                excerpt=excerpt,
                notes=notes,
            )
        )

    def add_error(self, message: str) -> None:
        if message:
            self.errors.append(message)

    def set_status(self, status: str, *, success: Optional[bool] = None) -> None:
        status = status.upper()
        if status not in VALID_STATUSES:
            raise ValueError(f"지원하지 않는 상태값입니다: {status}")
        self.status = status
        if success is None:
            self.success = status in {"PASS", "MANUAL"}
        else:
            self.success = success

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidences"] = [e.to_dict() for e in self.evidences]
        return data