# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import stat
import subprocess
import datetime

try:
    import pwd
except Exception:
    pwd = None

try:
    import grp
except Exception:
    grp = None

from app.compat import to_text
from app.collectors.file_reader import FileReader


class AccountPolicyReader(object):
    """
    계정 및 권한 관련 점검용 수집기

    [기존 기능]
    - group 파싱
    - pam_wheel 파싱
    - 파일 권한 검사

    [U-07 확장 기능]
    - /etc/passwd 파싱
    - last 명령 실행
    - 로그인 이력 분석
    - 불필요 계정 탐지
    """

    def __init__(self):
        self.file_reader = FileReader()

    # =========================
    # 공통
    # =========================

    def read_file(self, path):
        return self.file_reader.read(path)

    @staticmethod
    def file_exists(file_result):
        if file_result is None:
            return False

        try:
            return bool(file_result.metadata.exists)
        except Exception:
            return False

    # =========================
    # [NEW] passwd 파싱
    # =========================

    def parse_passwd_file(self, content):
        """
        /etc/passwd 파싱

        반환:
        {
            "accounts": [
                {
                    "username": "root",
                    "uid": 0,
                    "gid": 0,
                    "home": "/root",
                    "shell": "/bin/bash",
                    "raw_line": "..."
                }
            ]
        }
        """
        accounts = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 7:
                continue

            try:
                uid = int(parts[2])
                gid = int(parts[3])
            except Exception:
                continue

            accounts.append({
                "username": to_text(parts[0]),
                "uid": uid,
                "gid": gid,
                "home": to_text(parts[5]),
                "shell": to_text(parts[6]),
                "raw_line": line,
            })

        return {
            "accounts": accounts
        }

    # =========================
    # [NEW] last 실행
    # =========================

    def run_last(self):
        """
        last 명령 실행 (Python2/3 호환)
        """
        try:
            proc = subprocess.Popen(
                ["last", "-w"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            out, _ = proc.communicate()

            if out:
                return to_text(out)
        except Exception:
            pass

        return ""

    # =========================
    # [NEW] last 파싱
    # =========================

    def parse_last_output(self, content):
        """
        last 결과에서 로그인 사용자 목록 추출
        """
        users = set()

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("reboot"):
                continue

            parts = line.split()
            if not parts:
                continue

            username = to_text(parts[0]).strip()

            if username and username not in ("wtmp", "btmp"):
                users.add(username)

        return list(users)

    # =========================
    # [NEW] 불필요 계정 탐지
    # =========================

    def find_unnecessary_accounts(self, accounts, logged_in_users, policy):
        """
        불필요 계정 판별

        반환:
        {
            "unnecessary": [],
            "no_login": []
        }
        """
        default_accounts = policy.get("default_accounts", [])
        exclude_accounts = policy.get("exclude_accounts", [])

        unnecessary = []
        no_login = []

        for acc in accounts:
            username = to_text(acc.get("username"))

            # 제외 계정
            if username in exclude_accounts:
                continue

            # 기본 계정 → 바로 취약
            if username in default_accounts:
                unnecessary.append(acc)
                continue

            # 로그인 이력 없음 → 수동 점검
            if username not in logged_in_users:
                no_login.append(acc)

        return {
            "unnecessary": unnecessary,
            "no_login": no_login,
        }

    # =========================
    # 기존 코드 유지 (일부만 표시)
    # =========================

    def inspect_file(self, path):
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
    def _resolve_owner_name(uid):
        if pwd is None:
            return to_text(uid)

        try:
            return to_text(pwd.getpwuid(uid).pw_name)
        except Exception:
            return to_text(uid)

    @staticmethod
    def _resolve_group_name(gid):
        if grp is None:
            return to_text(gid)

        try:
            return to_text(grp.getgrgid(gid).gr_name)
        except Exception:
            return to_text(gid)