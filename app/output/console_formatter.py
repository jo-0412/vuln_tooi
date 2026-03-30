from __future__ import annotations

from typing import Optional
import json
import sys

from app.models.check_result import CheckResult, EvidenceItem


class ConsoleFormatter:
    def __init__(self, use_color: Optional[bool] = None) -> None:
        self.use_color = sys.stdout.isatty() if use_color is None else use_color

    def format(self, result: CheckResult, *, verbose: bool = True) -> str:
        lines: list[str] = []

        lines.append(f"[{result.code}] {result.name}")
        lines.append(f"상태: {self._colorize_status(result.status)}")
        lines.append(f"중요도: {result.severity}")
        lines.append(f"분류: {result.category}")
        lines.append(f"root 권한 필요 여부: {result.requires_root}")
        lines.append(f"점검 시각: {result.checked_at}")
        lines.append("")

        lines.append("요약")
        lines.append(f"- {result.summary}")
        lines.append("")

        lines.append("상세")
        for line in self._split_lines(result.detail):
            lines.append(f"- {line}")
        lines.append("")

        if result.remediation_summary or result.remediation_steps:
            lines.append("조치 안내")
            if result.remediation_summary:
                lines.append(f"- {result.remediation_summary}")
            for step in result.remediation_steps:
                lines.append(f"  • {step}")
            lines.append("")

        if verbose and result.evidences:
            lines.append("수집 증적")
            for evidence in result.evidences:
                lines.extend(self._format_evidence(evidence))
            lines.append("")

        if result.errors:
            lines.append("오류")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def format_json(self, result: CheckResult) -> str:
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)

    def print(self, result: CheckResult, *, verbose: bool = True) -> None:
        print(self.format(result, verbose=verbose), end="")

    def _format_evidence(self, evidence: EvidenceItem) -> list[str]:
        lines = [
            f"- {evidence.label}",
            f"  source: {evidence.source}",
            f"  value : {self._value_to_text(evidence.value)}",
        ]
        if evidence.status:
            lines.append(f"  state : {evidence.status}")
        if evidence.excerpt:
            lines.append(f"  excerpt: {evidence.excerpt}")
        if evidence.notes:
            lines.append(f"  notes  : {evidence.notes}")
        return lines

    @staticmethod
    def _split_lines(text: str) -> list[str]:
        return [line.strip() for line in text.splitlines() if line.strip()] or [""]

    @staticmethod
    def _value_to_text(value: object) -> str:
        if isinstance(value, (dict, list, tuple, set)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    def _colorize_status(self, status: str) -> str:
        if not self.use_color:
            return status

        color_map = {
            "PASS": "\033[32m",
            "FAIL": "\033[31m",
            "MANUAL": "\033[33m",
            "ERROR": "\033[35m",
        }
        reset = "\033[0m"
        color = color_map.get(status.upper(), "")
        return f"{color}{status}{reset}" if color else status