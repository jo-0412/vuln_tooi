# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import stat
import subprocess

try:
    import pwd
except Exception:  # pragma: no cover
    pwd = None

try:
    import grp
except Exception:  # pragma: no cover
    grp = None

from app.compat import to_text
from app.collectors.file_reader import FileReader


class AccountPolicyReader(object):
    """
    계정 및 권한 관련 점검용 수집기

    U-06 기능:
    - /etc/group 파싱
    - /etc/pam.d/su 내 pam_wheel 설정 파싱
    - su 실행 파일 메타데이터 확인

    U-07 기능:
    - /etc/passwd 파싱
    - last 명령 실행
    - 로그인 이력 사용자 추출
    - 불필요 계정 후보 탐지
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

    # ============================================================
    # U-06: group 파일 파싱
    # ============================================================

    def parse_group_file(self, content):
        """
        /etc/group 형식을 파싱한다.
        """
        active_lines = []
        groups = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("#"):
                continue

            active_lines.append(line)

            parts = line.split(":")
            if len(parts) < 4:
                continue

            group_name = to_text(parts[0]).strip()
            password = to_text(parts[1]).strip()
            gid = to_text(parts[2]).strip()
            members_text = to_text(parts[3]).strip()

            members = []
            if members_text:
                for item in members_text.split(","):
                    member = to_text(item).strip()
                    if member:
                        members.append(member)

            groups.append({
                "name": group_name,
                "password": password,
                "gid": gid,
                "members": members,
                "raw_line": line,
            })

        return {
            "groups": groups,
            "active_lines": active_lines,
        }

    @staticmethod
    def find_group(groups, allowed_group_names):
        """
        허용된 그룹명 목록 중 실제 존재하는 그룹을 찾는다.
        """
        normalized_allowed = []

        for item in allowed_group_names or []:
            name = to_text(item).strip()
            if name:
                normalized_allowed.append(name)

        for group in groups or []:
            group_name = to_text(group.get("name", "")).strip()
            if group_name in normalized_allowed:
                return group

        return None

    # ============================================================
    # U-06: /etc/pam.d/su 파싱
    # ============================================================

    def parse_su_pam(self, content, accepted_patterns=None, accepted_modules=None):
        """
        /etc/pam.d/su 파일에서 pam_wheel.so 설정 여부를 확인한다.
        """
        accepted_patterns = accepted_patterns or []
        accepted_modules = accepted_modules or ["pam_wheel.so"]

        active_lines = self._extract_active_lines(content)
        matched_line = ""
        matched_pattern = ""
        module_found = False
        pam_wheel_enabled = False
        pam_wheel_mode = ""

        normalized_patterns = []
        for item in accepted_patterns:
            pattern = to_text(item).strip()
            if pattern:
                normalized_patterns.append(pattern)

        normalized_modules = []
        for item in accepted_modules:
            module_name = to_text(item).strip()
            if module_name:
                normalized_modules.append(module_name)

        for line in active_lines:
            line_text = to_text(line).strip()

            for module_name in normalized_modules:
                if module_name in line_text:
                    module_found = True
                    break

            for pattern in normalized_patterns:
                if pattern == line_text:
                    pam_wheel_enabled = True
                    matched_line = line_text
                    matched_pattern = pattern
                    break

            if pam_wheel_enabled:
                break

        if module_found and (not pam_wheel_enabled):
            for line in active_lines:
                line_text = to_text(line).strip()

                if "pam_wheel.so" not in line_text:
                    continue

                matched_line = line_text

                if "group=wheel" in line_text:
                    pam_wheel_mode = "group=wheel"
                elif "use_uid" in line_text:
                    pam_wheel_mode = "use_uid"
                else:
                    pam_wheel_mode = "module_only"

                break

        if pam_wheel_enabled:
            if "group=wheel" in matched_line:
                pam_wheel_mode = "group=wheel"
            elif "use_uid" in matched_line:
                pam_wheel_mode = "use_uid"
            else:
                pam_wheel_mode = "matched_pattern"

        return {
            "active_lines": active_lines,
            "pam_wheel_enabled": pam_wheel_enabled,
            "pam_wheel_mode": pam_wheel_mode,
            "matched_line": matched_line,
            "matched_pattern": matched_pattern,
            "module_found": module_found,
        }

    # ============================================================
    # U-06: 파일 메타데이터 확인
    # ============================================================

    def inspect_file(self, path):
        """
        파일의 소유자/그룹/권한 메타데이터를 수집한다.
        """
        exists = os.path.exists(path)

        result = {
            "path": to_text(path),
            "exists": exists,
            "uid": None,
            "gid": None,
            "owner_name": "",
            "group_name": "",
            "mode_int": None,
            "mode_octal": "",
            "is_regular_file": False,
        }

        if not exists:
            return result

        try:
            st_obj = os.lstat(path)
        except Exception:
            return result

        result["uid"] = st_obj.st_uid
        result["gid"] = st_obj.st_gid
        result["owner_name"] = self._resolve_owner_name(st_obj.st_uid)
        result["group_name"] = self._resolve_group_name(st_obj.st_gid)
        result["mode_int"] = st_obj.st_mode & 0o7777
        result["mode_octal"] = "%04o" % (st_obj.st_mode & 0o7777)
        result["is_regular_file"] = stat.S_ISREG(st_obj.st_mode)

        return result

    @staticmethod
    def is_mode_at_most(current_mode_octal, max_mode_octal):
        """
        현재 권한이 기준 이하인지 비교한다.
        """
        try:
            current_value = int(to_text(current_mode_octal).strip(), 8)
            max_value = int(to_text(max_mode_octal).strip(), 8)
        except Exception:
            return False

        return current_value <= max_value

    @staticmethod
    def is_group_allowed(group_name, allowed_group_names):
        """
        파일 그룹이 허용 그룹 목록에 포함되는지 확인한다.
        """
        current_group = to_text(group_name).strip()

        for item in allowed_group_names or []:
            allowed_group = to_text(item).strip()
            if allowed_group and current_group == allowed_group:
                return True

        return False

    # ============================================================
    # U-07: /etc/passwd 파싱
    # ============================================================

    def parse_passwd_file(self, content):
        """
        /etc/passwd 형식을 파싱한다.
        """
        active_lines = []
        accounts = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("#"):
                continue

            active_lines.append(line)

            parts = line.split(":")
            if len(parts) < 7:
                continue

            username = to_text(parts[0]).strip()
            password_field = to_text(parts[1]).strip()
            uid_text = to_text(parts[2]).strip()
            gid_text = to_text(parts[3]).strip()
            gecos = to_text(parts[4]).strip()
            home = to_text(parts[5]).strip()
            shell = to_text(parts[6]).strip()

            try:
                uid = int(uid_text)
            except Exception:
                uid = None

            try:
                gid = int(gid_text)
            except Exception:
                gid = None

            accounts.append({
                "username": username,
                "password_field": password_field,
                "uid": uid,
                "gid": gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
                "raw_line": line,
            })

        return {
            "accounts": accounts,
            "active_lines": active_lines,
        }

    # ============================================================
    # U-07: last 명령 실행 및 파싱
    # ============================================================

    def run_last(self):
        """
        last 명령을 실행한다.
        """
        commands = [
            ["last", "-w"],
            ["last"],
        ]

        for command in commands:
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()

                if proc.returncode == 0 and stdout:
                    return to_text(stdout)

                if stdout:
                    return to_text(stdout)
            except Exception:
                continue

        return ""

    def parse_last_output(self, content):
        """
        last 출력에서 로그인 이력이 있는 사용자명을 추출한다.
        """
        users = []
        seen = set()

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if not line:
                continue

            lowered = line.lower()

            if lowered.startswith("wtmp"):
                continue
            if lowered.startswith("btmp"):
                continue
            if lowered.startswith("reboot"):
                continue
            if lowered.startswith("shutdown"):
                continue

            parts = line.split()
            if not parts:
                continue

            username = to_text(parts[0]).strip()

            if not username:
                continue

            if username not in seen:
                seen.add(username)
                users.append(username)

        return users

    # ============================================================
    # U-07: 불필요 계정 후보 탐지
    # ============================================================

    def find_unnecessary_accounts(self, accounts, logged_in_users, policy):
        """
        정책 기준으로 불필요 계정과 로그인 이력 없는 계정을 분류한다.
        """
        default_accounts = policy.get("default_accounts", [])
        exclude_accounts = policy.get("exclude_accounts", [])
        ignore_no_login_accounts = policy.get("ignore_no_login_accounts", [])

        logged_set = set()
        for user in logged_in_users or []:
            logged_set.add(to_text(user).strip())

        default_set = set()
        for user in default_accounts or []:
            default_set.add(to_text(user).strip())

        exclude_set = set()
        for user in exclude_accounts or []:
            exclude_set.add(to_text(user).strip())

        ignore_no_login_set = set()
        for user in ignore_no_login_accounts or []:
            ignore_no_login_set.add(to_text(user).strip())

        unnecessary = []
        no_login = []

        for account in accounts or []:
            username = to_text(account.get("username", "")).strip()

            if not username:
                continue

            if username in exclude_set:
                continue

            if username in default_set:
                unnecessary.append(account)
                continue

            if username in ignore_no_login_set:
                continue

            if username not in logged_set:
                no_login.append(account)

        return {
            "unnecessary": unnecessary,
            "no_login": no_login,
        }

    # ============================================================
    # 공통 유틸
    # ============================================================

    @staticmethod
    def _extract_active_lines(content):
        """
        주석과 공백 라인을 제거한 활성 설정 라인만 추출한다.
        """
        active_lines = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("#"):
                continue

            if "#" in line:
                line = line.split("#", 1)[0].strip()

            if line:
                active_lines.append(line)

        return active_lines

    @staticmethod
    def _resolve_owner_name(uid):
        """
        UID를 사용자명으로 변환한다.
        """
        if pwd is None:
            return to_text(uid)

        try:
            return to_text(pwd.getpwuid(uid).pw_name)
        except Exception:
            return to_text(uid)

    @staticmethod
    def _resolve_group_name(gid):
        """
        GID를 그룹명으로 변환한다.
        """
        if grp is None:
            return to_text(gid)

        try:
            return to_text(grp.getgrgid(gid).gr_name)
        except Exception:
            return to_text(gid)