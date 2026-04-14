# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import shlex
import subprocess

try:
    import shutil
except Exception:
    shutil = None

try:
    from distutils.spawn import find_executable
except Exception:  # pragma: no cover
    find_executable = None

from app.compat import to_text
from app.collectors.file_reader import FileReader
from app.collectors.service_reader import ServiceReader


class LoggingPolicyReader(object):
    """
    U-66용 로깅 정책 수집기
    - 설정 파일 읽기
    - 로깅 서비스 상태 확인
    - 명령 실행
    - 활성 설정 라인 추출
    """

    def __init__(self):
        self.file_reader = FileReader()
        self.service_reader = ServiceReader()

    def read_file(self, path):
        return self.file_reader.read(path)

    def inspect_service(self, name, aliases=None):
        aliases = aliases or []
        return self.service_reader.inspect(name, aliases=aliases)

    def command_exists(self, command_name):
        return self._which(command_name) is not None

    def run_command(self, command):
        command_text = to_text(command).strip()
        if not command_text:
            return {
                "status": "error",
                "available": False,
                "returncode": 999,
                "stdout": "",
                "stderr": "빈 명령입니다.",
                "command": command_text,
            }

        try:
            argv = shlex.split(command_text)
        except Exception as exc:
            return {
                "status": "error",
                "available": False,
                "returncode": 999,
                "stdout": "",
                "stderr": to_text(exc),
                "command": command_text,
            }

        if not argv:
            return {
                "status": "error",
                "available": False,
                "returncode": 999,
                "stdout": "",
                "stderr": "빈 명령입니다.",
                "command": command_text,
            }

        exe = argv[0]
        if not self.command_exists(exe):
            return {
                "status": "not_found",
                "available": False,
                "returncode": 127,
                "stdout": "",
                "stderr": "명령을 찾을 수 없습니다.",
                "command": command_text,
            }

        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()

            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "available": True,
                "returncode": proc.returncode,
                "stdout": to_text(stdout),
                "stderr": to_text(stderr),
                "command": command_text,
            }
        except Exception as exc:
            return {
                "status": "error",
                "available": True,
                "returncode": 999,
                "stdout": "",
                "stderr": to_text(exc),
                "command": command_text,
            }

    def extract_active_lines(self, content):
        active_lines = []

        for raw_line in to_text(content).splitlines():
            stripped = raw_line.strip()

            if (not stripped) or stripped.startswith("#"):
                continue

            line = stripped
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            if line:
                active_lines.append(line)

        return active_lines

    def filter_logging_policy_lines(self, lines, patterns):
        filtered = []

        for line in lines:
            text = to_text(line)
            lowered = text.lower()

            if "/var/log/" in text:
                filtered.append(text)
                continue

            for pattern in patterns:
                pattern_text = to_text(pattern).strip().lower()
                if pattern_text and pattern_text in lowered:
                    filtered.append(text)
                    break

        return self._dedupe_keep_order(filtered)

    def is_service_active(self, service_result):
        if service_result is None:
            return False

        try:
            return bool(service_result.active)
        except Exception:
            return False

    def file_exists(self, file_result):
        if file_result is None:
            return False

        try:
            return bool(file_result.metadata.exists)
        except Exception:
            return False

    @staticmethod
    def _dedupe_keep_order(items):
        seen = set()
        result = []

        for item in items:
            normalized = to_text(item).strip()
            if not normalized:
                continue
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    def _which(self, name):
        if shutil is not None and hasattr(shutil, "which"):
            try:
                found = shutil.which(name)
                if found:
                    return found
            except Exception:
                pass

        if find_executable is not None:
            try:
                found = find_executable(name)
                if found:
                    return found
            except Exception:
                pass

        return None