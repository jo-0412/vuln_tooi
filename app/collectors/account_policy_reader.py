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

    U-06:
    - /etc/group 파싱
    - /etc/pam.d/su 내 pam_wheel 설정 파싱
    - su 실행 파일 메타데이터 확인

    U-07:
    - /etc/passwd 파싱
    - last 명령 실행
    - 로그인 이력 사용자 추출
    - 불필요 계정 후보 탐지

    U-13:
    - /etc/shadow 해시 prefix 파싱
    - /etc/login.defs ENCRYPT_METHOD 파싱
    - PAM pam_unix.so 해시 알고리즘 옵션 파싱

    U-30:
    - /etc/profile 내 umask 설정 라인 파싱
    - /etc/login.defs 내 UMASK 설정 파싱
    - 현재 세션 umask 수집
    - 기준값 022 이상인지 권한 마스크 관점에서 판정

    U-63:
    - /etc/sudoers include 구조 파싱
    - /etc/sudoers.d 파일 목록 수집
    - sudoers 관련 경로 메타데이터 확인
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
    # 공통: 파일 메타데이터 확인
    # ============================================================

    def inspect_file(self, path):
        """
        파일/디렉터리의 소유자/그룹/권한 메타데이터를 수집한다.
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
            "is_directory": False,
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
        result["is_directory"] = stat.S_ISDIR(st_obj.st_mode)

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
    # U-13: /etc/shadow 해시 파싱
    # ============================================================

    def parse_shadow_hashes(self, content, hash_prefix_map=None, ignored_markers=None):
        """
        /etc/shadow에서 계정별 password hash prefix를 추출한다.
        """
        hash_prefix_map = hash_prefix_map or {}
        ignored_markers = ignored_markers or ["!", "*", "!!", "x", ""]

        accounts = []
        prefixes = []
        algorithms = []
        seen_prefixes = set()
        seen_algorithms = set()

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if (not line) or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 2:
                continue

            username = to_text(parts[0]).strip()
            password_hash = to_text(parts[1]).strip()

            active = not self._is_ignored_password_field(password_hash, ignored_markers)
            prefix = self._detect_hash_prefix(password_hash, hash_prefix_map)
            algorithm = self._map_hash_algorithm(password_hash, prefix, hash_prefix_map)

            item = {
                "username": username,
                "password_field_preview": self._mask_password_hash(password_hash),
                "active": active,
                "hash_prefix": prefix,
                "algorithm": algorithm,
                "raw_line_preview": username + ":" + self._mask_password_hash(password_hash),
            }

            accounts.append(item)

            if active and prefix and prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                prefixes.append(prefix)

            if active and algorithm and algorithm not in seen_algorithms:
                seen_algorithms.add(algorithm)
                algorithms.append(algorithm)

        return {
            "accounts": accounts,
            "hash_prefixes": prefixes,
            "algorithms": algorithms,
        }

    @staticmethod
    def _is_ignored_password_field(password_hash, ignored_markers):
        value = to_text(password_hash).strip()

        if value in ignored_markers:
            return True

        if value.startswith("!") or value.startswith("*"):
            return True

        return False

    @staticmethod
    def _detect_hash_prefix(password_hash, hash_prefix_map):
        value = to_text(password_hash).strip()
        prefixes = sorted(hash_prefix_map.keys(), key=lambda x: len(to_text(x)), reverse=True)

        for prefix in prefixes:
            prefix_text = to_text(prefix)
            if value.startswith(prefix_text):
                return prefix_text

        if value and value.startswith("$"):
            parts = value.split("$")
            if len(parts) >= 2 and parts[1]:
                return "$" + parts[1] + "$"

        return ""

    @staticmethod
    def _map_hash_algorithm(password_hash, prefix, hash_prefix_map):
        if prefix:
            return to_text(hash_prefix_map.get(prefix, "unknown")).lower()

        value = to_text(password_hash).strip()

        if not value:
            return ""

        if value.startswith("!") or value.startswith("*"):
            return "locked"

        return "des"

    @staticmethod
    def _mask_password_hash(password_hash):
        value = to_text(password_hash).strip()

        if not value:
            return ""

        if value in ("!", "*", "!!", "x"):
            return value

        if len(value) <= 8:
            return value[:2] + "******"

        return value[:8] + "...(masked)"

    # ============================================================
    # U-13: /etc/login.defs ENCRYPT_METHOD 파싱
    # ============================================================

    def parse_login_defs_encrypt_method(self, content):
        """
        /etc/login.defs에서 ENCRYPT_METHOD 값을 파싱한다.
        """
        active_lines = self._extract_active_lines(content)
        encrypt_method = ""
        matched_line = ""

        for line in active_lines:
            parts = line.split()
            if len(parts) < 2:
                continue

            key = to_text(parts[0]).strip()
            if key == "ENCRYPT_METHOD":
                encrypt_method = to_text(parts[1]).strip().upper()
                matched_line = line
                break

        return {
            "encrypt_method": encrypt_method,
            "matched_line": matched_line,
            "active_lines": active_lines,
        }

    # ============================================================
    # U-13: PAM pam_unix.so 해시 옵션 파싱
    # ============================================================

    def parse_pam_unix_hash_options(self, content, secure_options=None, weak_options=None):
        """
        PAM 파일에서 pam_unix.so 라인의 해시 알고리즘 옵션을 파싱한다.
        """
        secure_options = secure_options or []
        weak_options = weak_options or []

        active_lines = self._extract_active_lines(content)

        matched_lines = []
        detected_options = []
        secure_detected = []
        weak_detected = []

        for line in active_lines:
            line_text = to_text(line).strip()

            if "pam_unix.so" not in line_text:
                continue

            matched_lines.append(line_text)
            tokens = line_text.split()

            for token in tokens:
                token_lower = to_text(token).strip().lower()

                if token_lower in secure_options:
                    detected_options.append(token_lower)
                    secure_detected.append(token_lower)

                if token_lower in weak_options:
                    detected_options.append(token_lower)
                    weak_detected.append(token_lower)

        return {
            "matched_lines": self._dedupe_keep_order(matched_lines),
            "detected_options": self._dedupe_keep_order(detected_options),
            "secure_options": self._dedupe_keep_order(secure_detected),
            "weak_options": self._dedupe_keep_order(weak_detected),
        }

    # ============================================================
    # U-30: /etc/profile UMASK 파싱
    # ============================================================

    def parse_profile_umask_lines(self, content):
        """
        /etc/profile에서 umask 관련 활성 라인을 추출하고 값을 파싱한다.
        """
        active_lines = self._extract_active_lines(content)
        items = []

        for line in active_lines:
            lower_line = to_text(line).lower()

            if "umask" not in lower_line:
                continue

            value = self._extract_umask_value_from_line(line)

            items.append({
                "source": "/etc/profile",
                "line": line,
                "value": value,
                "valid": self.is_valid_umask_value(value),
            })

        return {
            "items": items,
            "lines": [item.get("line") for item in items],
            "values": self._dedupe_keep_order([item.get("value") for item in items if item.get("value")]),
        }

    # ============================================================
    # U-30: /etc/login.defs UMASK 파싱
    # ============================================================

    def parse_login_defs_umask(self, content):
        """
        /etc/login.defs에서 UMASK 값을 파싱한다.
        """
        active_lines = self._extract_active_lines(content)
        items = []

        for line in active_lines:
            parts = line.split()
            if len(parts) < 2:
                continue

            key = to_text(parts[0]).strip().upper()

            if key != "UMASK":
                continue

            value = to_text(parts[1]).strip()

            items.append({
                "source": "/etc/login.defs",
                "line": line,
                "value": value,
                "valid": self.is_valid_umask_value(value),
            })

        return {
            "items": items,
            "lines": [item.get("line") for item in items],
            "values": self._dedupe_keep_order([item.get("value") for item in items if item.get("value")]),
        }

    # ============================================================
    # U-30: 현재 세션 umask 수집
    # ============================================================

    def run_current_umask(self):
        """
        현재 프로세스 기준 umask를 직접 바꾸지 않고 shell을 통해 현재 세션 umask를 수집한다.
        """
        commands = [
            ["sh", "-c", "umask"],
            ["bash", "-lc", "umask"],
        ]

        for command in commands:
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()

                if stdout:
                    value = to_text(stdout).strip().splitlines()[0].strip()
                    return {
                        "value": value,
                        "status": "ok" if proc.returncode == 0 else "error",
                        "returncode": proc.returncode,
                        "stderr": to_text(stderr),
                        "command": " ".join(command),
                    }
            except Exception:
                continue

        return {
            "value": "",
            "status": "error",
            "returncode": 999,
            "stderr": "failed to run umask command",
            "command": "sh -c umask",
        }

    # ============================================================
    # U-30: UMASK 값 검증 및 비교
    # ============================================================

    @staticmethod
    def is_valid_umask_value(value):
        """
        UMASK 값이 3자리 또는 4자리 8진수 형태인지 확인한다.
        """
        text = to_text(value).strip()

        if not text:
            return False

        if len(text) not in (3, 4):
            return False

        for ch in text:
            if ch not in "01234567":
                return False

        return True

    @staticmethod
    def normalize_umask_value(value):
        """
        UMASK 값을 3자리 형태로 정규화한다.
        예: 0022 -> 022
        """
        text = to_text(value).strip()

        if len(text) == 4 and text.startswith("0"):
            text = text[1:]

        return text

    def is_umask_secure(self, value, required_value="022"):
        """
        UMASK가 기준값보다 같거나 더 엄격한지 판단한다.
        """
        if not self.is_valid_umask_value(value):
            return False

        if not self.is_valid_umask_value(required_value):
            required_value = "022"

        try:
            current = int(self.normalize_umask_value(value), 8)
            required = int(self.normalize_umask_value(required_value), 8)
        except Exception:
            return False

        return (current & required) == required

    @staticmethod
    def _extract_umask_value_from_line(line):
        """
        umask 설정 라인에서 값만 추출한다.
        """
        text = to_text(line).strip()

        if "#" in text:
            text = text.split("#", 1)[0].strip()

        text = text.replace("=", " ")
        tokens = text.split()

        for idx, token in enumerate(tokens):
            if token.lower() == "umask" and idx + 1 < len(tokens):
                candidate = tokens[idx + 1].strip().strip(";")
                return candidate

        return ""

    # ============================================================
    # U-63: sudoers include 구조 파싱
    # ============================================================

    def parse_sudoers_include_lines(self, content):
        """
        /etc/sudoers에서 include 또는 includedir 지시문을 수집한다.

        기능:
        - sudoers에서는 '#includedir'처럼 #으로 시작해도 주석이 아니라 지시문일 수 있다.
        - 일반 설정 파일처럼 '#' 라인을 모두 제거하면 안 된다.
        - @include, @includedir, #include, #includedir 모두 수집한다.

        반환:
        {
            "include_lines": [...],
            "include_dirs": [...],
            "include_files": [...]
        }
        """
        include_lines = []
        include_dirs = []
        include_files = []

        for raw_line in to_text(content).splitlines():
            line = raw_line.strip()

            if not line:
                continue

            lowered = line.lower()

            if not (
                lowered.startswith("#includedir") or
                lowered.startswith("@includedir") or
                lowered.startswith("#include") or
                lowered.startswith("@include")
            ):
                continue

            include_lines.append(line)

            parts = line.split()
            if len(parts) < 2:
                continue

            directive = to_text(parts[0]).lower()
            target = to_text(parts[1]).strip()

            if "includedir" in directive:
                include_dirs.append(target)
            else:
                include_files.append(target)

        return {
            "include_lines": include_lines,
            "include_dirs": self._dedupe_keep_order(include_dirs),
            "include_files": self._dedupe_keep_order(include_files),
        }

    def list_sudoers_d_files(self, directory="/etc/sudoers.d"):
        """
        /etc/sudoers.d 하위 파일 목록과 메타데이터를 수집한다.

        기능:
        - 디렉터리가 없으면 exists=False 반환
        - 파일마다 owner, group, mode를 inspect_file()로 수집
        - README처럼 일부 배포판에서 제공되는 설명 파일도 evidence로 남긴다.

        차별점:
        - sudoers.d 파일 내용까지 깊게 판정하지 않고 1차 구현에서는 권한 증적 중심으로 수집한다.
        - 상세 sudo 정책 분석은 이후 확장할 수 있다.
        """
        directory = to_text(directory).strip() or "/etc/sudoers.d"

        result = {
            "directory": directory,
            "exists": os.path.isdir(directory),
            "files": [],
            "errors": [],
        }

        if not result["exists"]:
            return result

        try:
            names = os.listdir(directory)
        except Exception as exc:
            result["errors"].append(to_text(exc))
            return result

        for name in sorted(names):
            if name in (".", ".."):
                continue

            path = os.path.join(directory, name)

            try:
                metadata = self.inspect_file(path)
                result["files"].append({
                    "path": path,
                    "name": name,
                    "exists": metadata.get("exists"),
                    "owner_name": metadata.get("owner_name"),
                    "group_name": metadata.get("group_name"),
                    "mode_octal": metadata.get("mode_octal"),
                    "is_regular_file": metadata.get("is_regular_file"),
                    "is_directory": metadata.get("is_directory"),
                })
            except Exception as exc:
                result["errors"].append(
                    "{0}: {1}".format(path, to_text(exc))
                )

        return result

    # ============================================================
    # 공통 유틸
    # ============================================================

    @staticmethod
    def _extract_active_lines(content):
        """
        주석과 공백 라인을 제거한 활성 설정 라인만 추출한다.

        주의:
        - sudoers의 #includedir은 주석처럼 보이지만 실제 지시문일 수 있으므로
          sudoers include 파싱에는 이 함수를 쓰지 않는다.
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
    def _dedupe_keep_order(items):
        """
        순서를 유지하면서 중복을 제거한다.
        """
        seen = set()
        result = []

        for item in items or []:
            normalized = to_text(item).strip()
            if not normalized:
                continue

            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

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