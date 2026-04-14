# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import re
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


class PackageUpdateReader(object):
    """
    U-64용 패키지/패치 상태 수집기
    - 설정 파일 읽기
    - 패키지 관리 명령 실행
    - 자동 업데이트 설정 파싱
    - 업그레이드 가능 패키지 목록 파싱
    - 최근 패치 이력 흔적 확인
    """

    def __init__(self):
        self.file_reader = FileReader()

    def read_file(self, path):
        return self.file_reader.read(path)

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

    def parse_auto_upgrade_config(self, content):
        lines = self.extract_active_lines(content)

        update_package_lists_enabled = False
        unattended_upgrade_enabled = False

        for line in lines:
            key, value = self._split_kv(line)
            lowered_key = key.lower()

            if "apt::periodic::update-package-lists" in lowered_key:
                update_package_lists_enabled = self._is_enabled_value(value)

            if "apt::periodic::unattended-upgrade" in lowered_key:
                unattended_upgrade_enabled = self._is_enabled_value(value)

        return {
            "active_lines": lines,
            "update_package_lists_enabled": update_package_lists_enabled,
            "unattended_upgrade_enabled": unattended_upgrade_enabled,
        }

    def parse_unattended_upgrade_config(self, content):
        lines = self.extract_active_lines(content)
        policy_lines = []

        for line in lines:
            lowered = to_text(line).lower()
            if (
                "unattended-upgrade" in lowered or
                "allowed-origins" in lowered or
                "origins-pattern" in lowered or
                "package-blacklist" in lowered
            ):
                policy_lines.append(line)

        return {
            "active_lines": lines,
            "policy_lines": policy_lines,
            "policy_present": bool(policy_lines),
        }

    def parse_apt_upgradable(self, stdout_text, stderr_text=""):
        text = "\n".join([
            to_text(stdout_text).strip(),
            to_text(stderr_text).strip()
        ]).strip()

        packages = []

        for raw_line in text.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            lowered = line.lower()

            if lowered.startswith("warning:"):
                continue
            if lowered.startswith("listing..."):
                continue

            if "/" not in line:
                continue

            if "upgradable from:" not in lowered:
                continue

            pkg_name = line.split("/", 1)[0].strip()
            current_version = ""
            candidate_version = ""

            bracket_match = re.search(r"\[upgradable from:\s*([^\]]+)\]", line, re.I)
            if bracket_match:
                current_version = to_text(bracket_match.group(1)).strip()

            before_bracket = line.split("[", 1)[0].strip()
            parts = before_bracket.split()

            if len(parts) >= 2:
                candidate_version = parts[1]

            packages.append({
                "package": pkg_name,
                "candidate_version": candidate_version,
                "current_version": current_version,
                "raw_line": line,
            })

        return packages

    def parse_hostnamectl(self, content):
        info = {
            "hostname": "",
            "operating_system": "",
            "kernel": "",
            "architecture": "",
            "virtualization": "",
        }

        for raw_line in to_text(content).splitlines():
            if ":" not in raw_line:
                continue

            key, value = raw_line.split(":", 1)
            key_text = to_text(key).strip().lower()
            value_text = to_text(value).strip()

            if key_text == "static hostname":
                info["hostname"] = value_text
            elif key_text == "operating system":
                info["operating_system"] = value_text
            elif key_text == "kernel":
                info["kernel"] = value_text
            elif key_text == "architecture":
                info["architecture"] = value_text
            elif key_text == "virtualization":
                info["virtualization"] = value_text

        return info

    def parse_uname_kernel(self, content):
        return to_text(content).strip()

    def has_patch_history(self, content):
        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()

            if (
                lowered.startswith("start-date:") or
                lowered.startswith("upgrade:") or
                lowered.startswith("install:") or
                lowered.startswith("remove:") or
                lowered.startswith("commandline:")
            ):
                return True

            if "unattended-upgrade" in lowered:
                return True

        return False

    def detect_unattended_installed(self, stdout_text, stderr_text=""):
        text = "\n".join([
            to_text(stdout_text).strip(),
            to_text(stderr_text).strip()
        ]).strip()

        for raw_line in text.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("ii") and "unattended-upgrades" in line:
                return True

        return False

    @staticmethod
    def _split_kv(line):
        text = to_text(line).strip()
        if ";" in text:
            text = text.rstrip(";").strip()

        if " " in text:
            key, value = text.split(" ", 1)
            return key.strip(), value.strip()

        return text, ""

    @staticmethod
    def _is_enabled_value(value):
        text = to_text(value).strip().strip('"').strip("'").lower()
        return text in ("1", "yes", "true", "on")

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