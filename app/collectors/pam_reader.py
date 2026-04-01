# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import re

from app.collectors.file_reader import FileReader


class PamEntry(object):
    def __init__(self, line_number, raw_line, interface, control,
                 module_path, module_name, arguments=None, options=None):
        self.line_number = line_number
        self.raw_line = raw_line
        self.interface = interface
        self.control = control
        self.module_path = module_path
        self.module_name = module_name
        self.arguments = arguments or []
        self.options = options or {}

    def to_dict(self):
        return {
            "line_number": self.line_number,
            "raw_line": self.raw_line,
            "interface": self.interface,
            "control": self.control,
            "module_path": self.module_path,
            "module_name": self.module_name,
            "arguments": self.arguments,
            "options": self.options,
        }


class PamParseResult(object):
    def __init__(self, path, status, success, message,
                 entries=None, line_count=0, metadata=None,
                 error_type=None, error_detail=None):
        self.path = path
        self.status = status
        self.success = success
        self.message = message
        self.entries = entries or []
        self.line_count = line_count
        self.metadata = metadata or {}
        self.error_type = error_type
        self.error_detail = error_detail

    def to_dict(self):
        return {
            "path": self.path,
            "status": self.status,
            "success": self.success,
            "message": self.message,
            "entries": [entry.to_dict() for entry in self.entries],
            "line_count": self.line_count,
            "metadata": self.metadata,
            "error_type": self.error_type,
            "error_detail": self.error_detail,
        }


class PamReader(object):
    """
    PAM 설정 파일 파서.
    common-password, system-auth 같은 파일을 읽어서
    모듈 존재 여부, 옵션 값, 적용 순서를 판별할 수 있도록 표준 형식으로 반환한다.
    """

    def __init__(self):
        self.file_reader = FileReader()

    def read(self, path):
        file_result = self.file_reader.read(path)
        if not file_result.success:
            return PamParseResult(
                path=path,
                status=file_result.status,
                success=False,
                message=file_result.message,
                entries=[],
                line_count=0,
                metadata=file_result.to_dict(),
                error_type=file_result.error_type,
                error_detail=file_result.error_detail,
            )

        return self.parse_text(
            file_result.content or "",
            path=path,
            metadata=file_result.to_dict()
        )

    def parse_text(self, content, path="<memory>", metadata=None):
        entries = []

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

    def find_modules(self, result, module_name):
        normalized = self._normalize_module_name(module_name)
        return [entry for entry in result.entries if entry.module_name == normalized]

    def has_module(self, result, module_name):
        return bool(self.find_modules(result, module_name))

    def get_first_module(self, result, module_name):
        modules = self.find_modules(result, module_name)
        return modules[0] if modules else None

    def get_first_option(self, result, module_names, option_name):
        for module_name in module_names:
            for entry in self.find_modules(result, module_name):
                if option_name in entry.options:
                    return entry.options[option_name], entry
        return None, None

    def get_module_line(self, result, module_name):
        entry = self.get_first_module(result, module_name)
        return entry.line_number if entry else None

    def check_order(self, result, before, after):
        before_line = self.get_module_line(result, before)
        after_line = self.get_module_line(result, after)

        if before_line is None or after_line is None:
            return None, before_line, after_line

        return before_line < after_line, before_line, after_line

    def build_module_summary(self, result):
        summary = {}
        for entry in result.entries:
            summary.setdefault(entry.module_name, []).append(entry.line_number)
        return summary

    def _parse_line(self, raw_line, line_number):
        stripped = raw_line.strip()

        if (not stripped) or stripped.startswith("#"):
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
    def _extract_control(remainder):
        if remainder.startswith("["):
            end_idx = remainder.find("]")
            if end_idx == -1:
                parts = remainder.split(None, 1)
                if len(parts) == 1:
                    return parts[0], ""
                return parts[0], parts[1]

            control = remainder[:end_idx + 1].strip()
            rest = remainder[end_idx + 1:].strip()
            return control, rest

        parts = remainder.split(None, 1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    @staticmethod
    def _parse_options(arguments):
        options = {}

        for arg in arguments:
            if "=" in arg:
                key, value = arg.split("=", 1)
                options[key.strip()] = value.strip()
            else:
                options[arg.strip()] = True

        return options

    @staticmethod
    def _normalize_module_name(module_path):
        return module_path.rsplit("/", 1)[-1]


def read_pam_file(path):
    reader = PamReader()
    return reader.read(path)