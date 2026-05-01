# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import subprocess

from app.compat import to_text
from app.collectors.file_reader import FileReader


class NetworkServiceReader(object):
    """
    네트워크 서비스 계열 점검용 수집기

    주요 기능:
    - 설정 파일 읽기
    - inetd.conf에서 활성 r 서비스 라인 탐지
    - xinetd.d 설정 파일에서 disable 값 파싱
    - systemd service/socket active/enabled 상태 확인
    - /etc/hosts.equiv, .rhosts 같은 신뢰 파일 탐색

    차별점:
    - AccountPolicyReader는 계정/권한 중심 수집기이다.
    - NetworkServiceReader는 서비스 설정, 서비스 상태, 신뢰 파일 탐색을 담당한다.
    - U-36뿐 아니라 이후 U-52 Telnet, U-54 FTP 같은 서비스 비활성화 항목에도 재사용 가능하다.
    """

    def __init__(self):
        self.file_reader = FileReader()

    def read_file(self, path):
        """
        공통 FileReader를 이용해 파일을 읽는다.
        """
        return self.file_reader.read(path)

    @staticmethod
    def file_exists(file_result):
        """
        FileReader 결과 객체에서 파일 존재 여부를 안전하게 확인한다.
        """
        if file_result is None:
            return False

        try:
            return bool(file_result.metadata.exists)
        except Exception:
            return False

    def parse_inetd_r_services(self, content, service_names=None):
        """
        /etc/inetd.conf에서 활성 r 계열 서비스 라인을 찾는다.

        기능:
        - 주석 라인 제거
        - rsh, rlogin, rexec, shell, login, exec 등 서비스명 탐지
        - 활성 라인만 evidence로 반환

        반환:
        {
            "active_entries": [...],
            "matched_services": [...]
        }
        """
        service_names = service_names or [
            "rsh",
            "rlogin",
            "rexec",
            "shell",
            "login",
            "exec",
        ]

        active_entries = []
        matched_services = []
        seen = set()

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if "#" in line:
                line = line.split("#", 1)[0].strip()

            if not line:
                continue

            lowered = line.lower()
            tokens = lowered.split()

            matched = []
            for service in service_names:
                service_text = to_text(service).lower().strip()
                if not service_text:
                    continue

                if service_text in tokens or service_text in lowered:
                    matched.append(service_text)

            if matched:
                active_entries.append(line)
                for item in matched:
                    if item not in seen:
                        seen.add(item)
                        matched_services.append(item)

        return {
            "active_entries": active_entries,
            "matched_services": matched_services,
        }

    def parse_xinetd_r_service(self, content, service_name=""):
        """
        xinetd 설정 파일에서 disable 값을 파싱한다.

        기능:
        - service 블록 전체를 정밀하게 파싱하지는 않는다.
        - 1차 구현에서는 파일 내 disable = yes/no 여부를 중심으로 본다.
        - disable = no 이면 활성 가능성이 높으므로 취약 신호로 본다.
        - disable 값이 없으면 자동 판정이 어려워 manual 대상으로 둔다.

        반환:
        {
            "service_name": "rsh",
            "disable_value": "yes",
            "active_lines": [...],
            "matched_lines": [...]
        }
        """
        active_lines = self._extract_active_lines(content)
        disable_value = ""
        matched_lines = []

        for line in active_lines:
            normalized = to_text(line).strip()
            lowered = normalized.lower()

            if "disable" not in lowered:
                continue

            # disable = yes, disable yes 둘 다 처리
            compare = lowered.replace("=", " ")
            parts = compare.split()

            for idx, part in enumerate(parts):
                if part == "disable" and idx + 1 < len(parts):
                    disable_value = to_text(parts[idx + 1]).strip().lower()
                    matched_lines.append(normalized)
                    break

        return {
            "service_name": to_text(service_name),
            "disable_value": disable_value,
            "active_lines": active_lines,
            "matched_lines": matched_lines,
        }

    def inspect_systemd_service(self, name, aliases=None):
        """
        systemd에서 service/socket 상태를 확인한다.

        기능:
        - systemctl is-active
        - systemctl is-enabled
        - aliases 목록을 함께 검사
        - systemctl이 없거나 unit이 없으면 not-found/unknown 성격으로 반환

        반환:
        {
            "name": "rsh",
            "units": [
                {
                    "unit": "rsh.service",
                    "active_state": "inactive",
                    "enabled_state": "disabled",
                    "active": False,
                    "enabled": False
                }
            ],
            "active": False,
            "enabled": False
        }
        """
        aliases = aliases or []

        units = []
        seen = set()

        candidates = [name]
        for alias in aliases:
            candidates.append(alias)

        normalized_candidates = []
        for candidate in candidates:
            text = to_text(candidate).strip()
            if not text:
                continue
            if text not in seen:
                seen.add(text)
                normalized_candidates.append(text)

        for unit in normalized_candidates:
            active_info = self._run_systemctl_state("is-active", unit)
            enabled_info = self._run_systemctl_state("is-enabled", unit)

            active_state = active_info.get("stdout", "").strip()
            enabled_state = enabled_info.get("stdout", "").strip()

            if not active_state:
                active_state = self._state_from_returncode(active_info)

            if not enabled_state:
                enabled_state = self._state_from_returncode(enabled_info)

            unit_item = {
                "unit": unit,
                "active_state": active_state,
                "enabled_state": enabled_state,
                "active": active_state == "active",
                "enabled": enabled_state == "enabled",
                "active_returncode": active_info.get("returncode"),
                "enabled_returncode": enabled_info.get("returncode"),
                "active_stderr": active_info.get("stderr", ""),
                "enabled_stderr": enabled_info.get("stderr", ""),
            }

            units.append(unit_item)

        any_active = False
        any_enabled = False

        for item in units:
            if item.get("active"):
                any_active = True
            if item.get("enabled"):
                any_enabled = True

        return {
            "name": to_text(name),
            "units": units,
            "active": any_active,
            "enabled": any_enabled,
        }

    def find_trust_files(self, roots=None, names=None):
        """
        r 계열 신뢰 파일을 탐색한다.

        기능:
        - /home, /root 아래에서 .rhosts, hosts.equiv 탐색
        - 접근 실패 경로는 warnings에 저장
        - 존재하는 신뢰 파일은 취약 신호로 사용 가능

        차별점:
        - 단순 find 명령 결과에 의존하지 않고 Python os.walk 기반으로 동작한다.
        - Python 2.7 환경에서도 동일하게 동작한다.
        """
        roots = roots or ["/home", "/root"]
        names = names or [".rhosts", "hosts.equiv"]

        normalized_names = set()
        for name in names:
            text = to_text(name).strip()
            if text:
                normalized_names.add(text)

        found = []
        warnings = []
        missing_roots = []

        for root in roots:
            root_path = os.path.abspath(to_text(root).strip())

            if not os.path.exists(root_path):
                missing_roots.append(root_path)
                continue

            if os.path.isfile(root_path):
                base = os.path.basename(root_path)
                if base in normalized_names:
                    found.append(self._build_trust_file_item(root_path))
                continue

            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                for filename in filenames:
                    if filename in normalized_names:
                        full_path = os.path.join(dirpath, filename)
                        found.append(self._build_trust_file_item(full_path))

        return {
            "found": found,
            "warnings": warnings,
            "missing_roots": missing_roots,
        }

    def _build_trust_file_item(self, path):
        item = {
            "path": to_text(path),
            "exists": os.path.exists(path),
            "owner_name": "",
            "group_name": "",
            "mode_octal": "",
        }

        try:
            st_obj = os.lstat(path)
            item["mode_octal"] = "%04o" % (st_obj.st_mode & 0o7777)
            item["owner_name"] = self._resolve_owner_name(st_obj.st_uid)
            item["group_name"] = self._resolve_group_name(st_obj.st_gid)
        except Exception:
            pass

        return item

    def _run_systemctl_state(self, action, unit):
        """
        systemctl 상태 조회를 수행한다.
        """
        command = ["systemctl", action, unit]

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()

            return {
                "command": " ".join(command),
                "returncode": proc.returncode,
                "stdout": to_text(stdout).strip(),
                "stderr": to_text(stderr).strip(),
            }
        except Exception as exc:
            return {
                "command": " ".join(command),
                "returncode": 999,
                "stdout": "",
                "stderr": to_text(exc),
            }

    @staticmethod
    def _state_from_returncode(command_result):
        """
        systemctl 결과가 비어 있을 때 returncode 기반으로 보조 상태를 만든다.
        """
        rc = command_result.get("returncode")

        if rc == 0:
            return "ok"

        stderr = to_text(command_result.get("stderr", "")).lower()

        if "could not be found" in stderr:
            return "not-found"

        if "not-found" in stderr:
            return "not-found"

        if rc == 3:
            return "inactive"

        if rc == 1:
            return "disabled"

        if rc == 999:
            return "unknown"

        return "unknown"

    @staticmethod
    def _extract_active_lines(content):
        """
        주석과 공백 라인을 제거한 활성 설정 라인만 추출한다.
        """
        active_lines = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if "#" in line:
                line = line.split("#", 1)[0].strip()

            if line:
                active_lines.append(line)

        return active_lines

    @staticmethod
    def _resolve_owner_name(uid):
        try:
            import pwd
            return to_text(pwd.getpwuid(uid).pw_name)
        except Exception:
            return to_text(uid)

    @staticmethod
    def _resolve_group_name(gid):
        try:
            import grp
            return to_text(grp.getgrgid(gid).gr_name)
        except Exception:
            return to_text(gid)