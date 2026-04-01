from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
import re

from app.collectors.file_reader import FileReader


@dataclass
class PamEntry:
    line_number: int
    raw_line: str
    interface: str
    control: str
    module_path: str
    module_name: str
    arguments: list[str] = field(default_factory=list)
    options: dict[str, str | bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PamParseResult:
    path: str
    status: str
    success: bool
    message: str
    entries: list[PamEntry] = field(default_factory=list)
    line_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    error_type: Optional[str] = None
    error_detail: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["entries"] = [entry.to_dict() for entry in self.entries]
        return data


class PamReader:
    """
    PAM 설정 파일 파서.
    common-password, system-auth 같은 파일을 읽어서
    모듈 존재 여부, 옵션 값, 적용 순서를 판별할 수 있도록 표준 형식으로 반환한다.
    """

    def __init__(self) -> None:
        self.file_reader = FileReader()

    def read(self, path: str | Path) -> PamParseResult:
        file_result = self.file_reader.read(path)
        if not file_result.success:
            return PamParseResult(
                path=str(path),
                status=file_result.status,
                success=False,
                message=file_result.message,
                entries=[],
                line_count=0,
                metadata=file_result.to_dict(),
                error_type=file_result.error_type,
                error_detail=file_result.error_detail,
            )

        return self.parse_text(file_result.content or "", path=str(path), metadata=file_result.to_dict())

    def parse_text(
        self,
        content: str,
        *,
        path: str = "<memory>",
        metadata: Optional[dict[str, Any]] = None,
    ) -> PamParseResult:
        entries: list[PamEntry] = []

        for idx, raw_line in enumerate(content.splitlines(), start=1):
            entry = self._parse_line(raw_line, idx)
            if entry is not None:
                entries.append(entry)

        return PamParseResult(
            path=path,
            status="ok",
            success=True,
            message="PAM 설정 파싱에 성공했습니다.",
            entries=entries,
            line_count=len(content.splitlines()),
            metadata=metadata or {},
        )

    def find_modules(self, result: PamParseResult, module_name: str) -> list[PamEntry]:
        normalized = self._normalize_module_name(module_name)
        return [entry for entry in result.entries if entry.module_name == normalized]

    def has_module(self, result: PamParseResult, module_name: str) -> bool:
        return bool(self.find_modules(result, module_name))

    def get_first_module(self, result: PamParseResult, module_name: str) -> Optional[PamEntry]:
        modules = self.find_modules(result, module_name)
        return modules[0] if modules else None

    def get_first_option(
        self,
        result: PamParseResult,
        module_names: list[str],
        option_name: str,
    ) -> tuple[Optional[str | bool], Optional[PamEntry]]:
        for module_name in module_names:
            for entry in self.find_modules(result, module_name):
                if option_name in entry.options:
                    return entry.options[option_name], entry
        return None, None

    def get_module_line(self, result: PamParseResult, module_name: str) -> Optional[int]:
        entry = self.get_first_module(result, module_name)
        return entry.line_number if entry else None

    def check_order(
        self,
        result: PamParseResult,
        *,
        before: str,
        after: str,
    ) -> tuple[Optional[bool], Optional[int], Optional[int]]:
        before_line = self.get_module_line(result, before)
        after_line = self.get_module_line(result, after)

        if before_line is None or after_line is None:
            return None, before_line, after_line

        return before_line < after_line, before_line, after_line

    def build_module_summary(self, result: PamParseResult) -> dict[str, list[int]]:
        summary: dict[str, list[int]] = {}
        for entry in result.entries:
            summary.setdefault(entry.module_name, []).append(entry.line_number)
        return summary

    def _parse_line(self, raw_line: str, line_number: int) -> Optional[PamEntry]:
        stripped = raw_line.strip()

        if not stripped or stripped.startswith("#"):
            return None

        line = re.sub(r"\s+#.*$", "", stripped).strip()
        if not line:
            return None

        interface_match = re.match(r"^(auth|account|password|session)\s+", line)
        if not interface_match:
            return None

        interface = interface_match.group(1)
        remainder = line[interface_match.end():].strip()
        if not remainder:
            return None

        control, remainder = self._extract_control(remainder)
        if not remainder:
            return None

        parts = remainder.split()
        if not parts:
            return None

        module_path = parts[0]
        arguments = parts[1:]
        module_name = self._normalize_module_name(module_path)
        options = self._parse_options(arguments)

        return PamEntry(
            line_number=line_number,
            raw_line=raw_line.rstrip("\n"),
            interface=interface,
            control=control,
            module_path=module_path,
            module_name=module_name,
            arguments=arguments,
            options=options,
        )

    @staticmethod
    def _extract_control(remainder: str) -> tuple[str, str]:
        if remainder.startswith("["):
            end_idx = remainder.find("]")
            if end_idx == -1:
                parts = remainder.split(maxsplit=1)
                if len(parts) == 1:
                    return parts[0], ""
                return parts[0], parts[1]

            control = remainder[: end_idx + 1].strip()
            rest = remainder[end_idx + 1 :].strip()
            return control, rest

        parts = remainder.split(maxsplit=1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    @staticmethod
    def _parse_options(arguments: list[str]) -> dict[str, str | bool]:
        options: dict[str, str | bool] = {}

        for arg in arguments:
            if "=" in arg:
                key, value = arg.split("=", 1)
                options[key.strip()] = value.strip()
            else:
                options[arg.strip()] = True

        return options

    @staticmethod
    def _normalize_module_name(module_path: str) -> str:
        return module_path.rsplit("/", 1)[-1]


def read_pam_file(path: str | Path) -> PamParseResult:
    reader = PamReader()
    return reader.read(path)