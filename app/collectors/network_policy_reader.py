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


class NetworkPolicyReader(object):
    """
    U-28용 네트워크/접근통제 정보 수집기
    - 파일 읽기
    - 명령 실행
    - sshd_config 파싱
    - 리스닝 포트 파싱
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

    def parse_sshd_config(self, content):
        ports = []
        listen_addresses = []
        active_lines = self.extract_active_lines(content)

        for line in active_lines:
            parts = re.split(r"\s+", line, 1)
            if len(parts) < 2:
                continue

            key = to_text(parts[0]).strip().lower()
            value = to_text(parts[1]).strip()

            if key == "port":
                ports.append(value)
            elif key == "listenaddress":
                listen_addresses.append(value)

        return {
            "ports": ports,
            "listen_addresses": listen_addresses,
            "active_lines": active_lines,
        }

    def parse_listening_ports(self, output):
        text = to_text(output)
        items = []

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if (not line) or line.startswith("Netid") or line.startswith("State"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 5:
                continue

            proto = parts[0]
            local_field = parts[4]
            process = ""
            if len(parts) >= 7:
                process = " ".join(parts[6:])
            elif len(parts) >= 6:
                process = parts[5]

            address, port = self._split_address_port(local_field)

            items.append({
                "proto": proto,
                "local_address": address,
                "port": port,
                "process": process,
            })

        return items

    @staticmethod
    def has_any_pattern(text, patterns):
        haystack = to_text(text)
        for pattern in patterns:
            if to_text(pattern) in haystack:
                return True
        return False

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

    @staticmethod
    def _split_address_port(value):
        text = to_text(value).strip()

        if not text:
            return "", ""

        if text.startswith("[") and "]:" in text:
            address, port = text.rsplit("]:", 1)
            return address + "]", port

        if text.count(":") >= 1:
            address, port = text.rsplit(":", 1)
            return address, port

        return text, ""